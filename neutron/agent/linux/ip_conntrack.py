#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import re

import netaddr
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron._i18n import _LE
from neutron.agent.linux import utils as linux_utils
from neutron.common import constants as n_const
from neutron.common import exceptions as n_exc

LOG = logging.getLogger(__name__)
CONTRACK_MGRS = {}
MAX_CONNTRACK_ZONES = 65535


@lockutils.synchronized('conntrack')
def get_conntrack(get_rules_for_table_func, filtered_ports, unfiltered_ports,
                  execute=None, namespace=None):

    try:
        return CONTRACK_MGRS[namespace]
    except KeyError:
        ipconntrack = IpConntrackManager(get_rules_for_table_func,
                                         filtered_ports, unfiltered_ports,
                                         execute, namespace)
        CONTRACK_MGRS[namespace] = ipconntrack
        return CONTRACK_MGRS[namespace]


class IpConntrackManager(object):
    """Smart wrapper for ip conntrack."""

    def __init__(self, get_rules_for_table_func, filtered_ports,
                 unfiltered_ports, execute=None, namespace=None):
        self.get_rules_for_table_func = get_rules_for_table_func
        self.execute = execute or linux_utils.execute
        self.namespace = namespace
        self.filtered_ports = filtered_ports
        self.unfiltered_ports = unfiltered_ports
        self._populate_initial_zone_map()

    @staticmethod
    def _generate_conntrack_cmd_by_rule(rule, namespace):
        ethertype = rule.get('ethertype')
        protocol = rule.get('protocol')
        direction = rule.get('direction')
        cmd = ['conntrack', '-D']
        if protocol:
            cmd.extend(['-p', str(protocol)])
        cmd.extend(['-f', str(ethertype).lower()])
        cmd.append('-d' if direction == 'ingress' else '-s')
        cmd_ns = []
        if namespace:
            cmd_ns.extend(['ip', 'netns', 'exec', namespace])
        cmd_ns.extend(cmd)
        return cmd_ns

    def _get_conntrack_cmds(self, device_info_list, rule, remote_ip=None):
        conntrack_cmds = set()
        cmd = self._generate_conntrack_cmd_by_rule(rule, self.namespace)
        ethertype = rule.get('ethertype')
        for device_info in device_info_list:
            zone_id = self._device_zone_map.get(device_info['device'], None)
            ips = device_info.get('fixed_ips', [])
            for ip in ips:
                net = netaddr.IPNetwork(ip)
                if str(net.version) not in ethertype:
                    continue
                ip_cmd = [str(net.ip)]
                if zone_id:
                    ip_cmd.extend(['-w', zone_id])
                if remote_ip and str(
                        netaddr.IPNetwork(remote_ip).version) in ethertype:
                    if rule.get('direction') == 'ingress':
                        direction = '-s'
                    else:
                        direction = '-d'
                    ip_cmd.extend([direction, str(remote_ip)])
                conntrack_cmds.add(tuple(cmd + ip_cmd))
        return conntrack_cmds

    def _delete_conntrack_state(self, device_info_list, rule, remote_ip=None):
        conntrack_cmds = self._get_conntrack_cmds(device_info_list,
                                                  rule, remote_ip)
        for cmd in conntrack_cmds:
            try:
                self.execute(list(cmd), run_as_root=True,
                             check_exit_code=True,
                             extra_ok_codes=[1])
            except RuntimeError:
                LOG.exception(
                    _LE("Failed execute conntrack command %s"), cmd)

    def delete_conntrack_state_by_rule(self, device_info_list, rule):
        self._delete_conntrack_state(device_info_list, rule)

    def delete_conntrack_state_by_remote_ips(self, device_info_list,
                                             ethertype, remote_ips):
        for direction in ['ingress', 'egress']:
            rule = {'ethertype': str(ethertype).lower(),
                    'direction': direction}
            if remote_ips:
                for remote_ip in remote_ips:
                    self._delete_conntrack_state(
                        device_info_list, rule, remote_ip)
            else:
                self._delete_conntrack_state(device_info_list, rule)

    def _populate_initial_zone_map(self):
        """Setup the map between devices and zones based on current rules."""
        self._device_zone_map = {}
        rules = self.get_rules_for_table_func('raw')
        for rule in rules:
            match = re.match(r'.* --physdev-in (?P<dev>[a-zA-Z0-9\-]+)'
                             r'.* -j CT --zone (?P<zone>\d+).*', rule)
            if match:
                # strip off any prefix that the interface is using
                short_port_id = (match.group('dev')
                    [n_const.LINUX_DEV_PREFIX_LEN:])
                self._device_zone_map[short_port_id] = int(match.group('zone'))
        LOG.debug("Populated conntrack zone map: %s", self._device_zone_map)

    def get_device_zone(self, port_id):
        # we have to key the device_zone_map based on the fragment of the port
        # UUID that shows up in the interface name. This is because the initial
        # map is populated strictly based on interface names that we don't know
        # the full UUID of.
        short_port_id = port_id[:(n_const.LINUX_DEV_LEN -
                                  n_const.LINUX_DEV_PREFIX_LEN)]
        try:
            return self._device_zone_map[short_port_id]
        except KeyError:
            return self._generate_device_zone(short_port_id)

    def _free_zones_from_removed_ports(self):
        """Clears any entries from the zone map of removed ports."""
        existing_ports = [
            port['device'][:(n_const.LINUX_DEV_LEN -
                             n_const.LINUX_DEV_PREFIX_LEN)]
            for port in (list(self.filtered_ports.values()) +
                         list(self.unfiltered_ports.values()))
        ]
        removed = set(self._device_zone_map) - set(existing_ports)
        for dev in removed:
            self._device_zone_map.pop(dev, None)

    def _generate_device_zone(self, short_port_id):
        """Generates a unique conntrack zone for the passed in ID."""
        try:
            zone = self._find_open_zone()
        except n_exc.CTZoneExhaustedError:
            # Free some zones and try again, repeat failure will not be caught
            self._free_zones_from_removed_ports()
            zone = self._find_open_zone()

        self._device_zone_map[short_port_id] = zone
        LOG.debug("Assigned CT zone %(z)s to port %(dev)s.",
                  {'z': zone, 'dev': short_port_id})
        return self._device_zone_map[short_port_id]

    def _find_open_zone(self):
        # call set to dedup because old ports may be mapped to the same zone.
        zones_in_use = sorted(set(self._device_zone_map.values()))
        if not zones_in_use:
            return 1
        # attempt to increment onto the highest used zone first. if we hit the
        # end, go back and look for any gaps left by removed devices.
        last = zones_in_use[-1]
        if last < MAX_CONNTRACK_ZONES:
            return last + 1
        for index, used in enumerate(zones_in_use):
            if used - index != 1:
                # gap found, let's use it!
                return index + 1
        # conntrack zones exhausted :( :(
        raise n_exc.CTZoneExhaustedError()
