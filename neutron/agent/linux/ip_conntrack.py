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

import eventlet
import netaddr
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron.agent.linux import utils as linux_utils
from neutron.common import constants as n_const
from neutron.common import exceptions as n_exc

LOG = logging.getLogger(__name__)
CONTRACK_MGRS = {}
MAX_CONNTRACK_ZONES = 65535
ZONE_START = 4097

WORKERS = 8


class IpConntrackUpdate(object):
    """Encapsulates a conntrack update

    An instance of this object carries the information necessary to
    process a request to update the conntrack table.
    """
    def __init__(self, device_info_list, rule, remote_ips):
        self.device_info_list = device_info_list
        self.rule = rule
        self.remote_ips = remote_ips

    def __repr__(self):
        return ('<IpConntrackUpdate(device_info_list=%s, rule=%s, '
                'remote_ips=%s>' % (self.device_info_list, self.rule,
                                    self.remote_ips))


@lockutils.synchronized('conntrack')
def get_conntrack(get_rules_for_table_func, filtered_ports, unfiltered_ports,
                  execute=None, namespace=None, zone_per_port=False):
    try:
        return CONTRACK_MGRS[namespace]
    except KeyError:
        ipconntrack = IpConntrackManager(get_rules_for_table_func,
                                         filtered_ports, unfiltered_ports,
                                         execute, namespace, zone_per_port)
        CONTRACK_MGRS[namespace] = ipconntrack
        return CONTRACK_MGRS[namespace]


class IpConntrackManager(object):
    """Smart wrapper for ip conntrack."""

    def __init__(self, get_rules_for_table_func, filtered_ports,
                 unfiltered_ports, execute=None, namespace=None,
                 zone_per_port=False):
        self.get_rules_for_table_func = get_rules_for_table_func
        self.execute = execute or linux_utils.execute
        self.namespace = namespace
        self.filtered_ports = filtered_ports
        self.unfiltered_ports = unfiltered_ports
        self.zone_per_port = zone_per_port  # zone per port vs per network
        self._populate_initial_zone_map()
        self._queue = eventlet.queue.LightQueue()
        self._start_process_queue()

    def _start_process_queue(self):
        LOG.debug("Starting ip_conntrack _process_queue_worker() threads")
        pool = eventlet.GreenPool(size=WORKERS)
        for i in range(WORKERS):
            pool.spawn_n(self._process_queue_worker)

    def _process_queue_worker(self):
        # While it's technically not necessary to have this method, the
        # 'while True' could just be in _process_queue(), the tests have
        # to be able to drain the queue without blocking, so _process_queue()
        # is made standalone.
        while True:
            self._process_queue()

    def _process_queue(self):
        update = None
        try:
            # this will block until an entry gets added to the queue
            update = self._queue.get()
            if update.remote_ips:
                for remote_ip in update.remote_ips:
                    self._delete_conntrack_state(
                        update.device_info_list, update.rule, remote_ip)
            else:
                self._delete_conntrack_state(
                    update.device_info_list, update.rule)
        except Exception:
            LOG.exception("Failed to process ip_conntrack queue entry: %s",
                          update)

    def _process(self, device_info_list, rule, remote_ips=None):
        # queue the update to allow the caller to resume its work
        update = IpConntrackUpdate(device_info_list, rule, remote_ips)
        self._queue.put(update)

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
            zone_id = self.get_device_zone(device_info, create=False)
            if not zone_id:
                LOG.debug("No zone for device %(dev)s. Will not try to "
                          "clear conntrack state. Zone map: %(zm)s",
                          {'dev': device_info['device'],
                           'zm': self._device_zone_map})
                continue
            ips = device_info.get('fixed_ips', [])
            for ip in ips:
                net = netaddr.IPNetwork(ip)
                if str(net.version) not in ethertype:
                    continue
                ip_cmd = [str(net.ip), '-w', zone_id]
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
                LOG.exception("Failed execute conntrack command %s", cmd)

    def delete_conntrack_state_by_rule(self, device_info_list, rule):
        self._process(device_info_list, rule)

    def delete_conntrack_state_by_remote_ips(self, device_info_list,
                                             ethertype, remote_ips):
        for direction in ['ingress', 'egress']:
            rule = {'ethertype': str(ethertype).lower(),
                    'direction': direction}
            self._process(device_info_list, rule, remote_ips)

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

    def _device_key(self, port):
        # we have to key the device_zone_map based on the fragment of the
        # UUID that shows up in the interface name. This is because the initial
        # map is populated strictly based on interface names that we don't know
        # the full UUID of.
        if self.zone_per_port:
            identifier = port['device'][n_const.LINUX_DEV_PREFIX_LEN:]
        else:
            identifier = port['network_id']
        return identifier[:(n_const.LINUX_DEV_LEN -
                          n_const.LINUX_DEV_PREFIX_LEN)]

    def get_device_zone(self, port, create=True):
        device_key = self._device_key(port)
        try:
            return self._device_zone_map[device_key]
        except KeyError:
            if create:
                return self._generate_device_zone(device_key)

    def _free_zones_from_removed_ports(self):
        """Clears any entries from the zone map of removed ports."""
        existing_ports = [
            self._device_key(port)
            for port in (list(self.filtered_ports.values()) +
                         list(self.unfiltered_ports.values()))
        ]
        removed = set(self._device_zone_map) - set(existing_ports)
        for dev in removed:
            self._device_zone_map.pop(dev, None)

    def _generate_device_zone(self, short_device_id):
        """Generates a unique conntrack zone for the passed in ID."""
        try:
            zone = self._find_open_zone()
        except n_exc.CTZoneExhaustedError:
            # Free some zones and try again, repeat failure will not be caught
            self._free_zones_from_removed_ports()
            zone = self._find_open_zone()

        self._device_zone_map[short_device_id] = zone
        LOG.debug("Assigned CT zone %(z)s to device %(dev)s.",
                  {'z': zone, 'dev': short_device_id})
        return self._device_zone_map[short_device_id]

    def _find_open_zone(self):
        # call set to dedup because old ports may be mapped to the same zone.
        zones_in_use = sorted(set(self._device_zone_map.values()))
        if not zones_in_use:
            return ZONE_START
        # attempt to increment onto the highest used zone first. if we hit the
        # end, go back and look for any gaps left by removed devices.
        last = zones_in_use[-1]
        if last < MAX_CONNTRACK_ZONES:
            return max(last + 1, ZONE_START)
        for index, used in enumerate(zones_in_use):
            if used - index != ZONE_START:
                # gap found, let's use it!
                return index + ZONE_START
        # conntrack zones exhausted :( :(
        raise n_exc.CTZoneExhaustedError()
