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

import netaddr
from oslo_log import log as logging

from neutron._i18n import _LE
from neutron.agent.linux import utils as linux_utils

LOG = logging.getLogger(__name__)


class IpConntrackManager(object):
    """Smart wrapper for ip conntrack."""

    def __init__(self, zone_lookup_func, execute=None, namespace=None):
        self.get_device_zone = zone_lookup_func
        self.execute = execute or linux_utils.execute
        self.namespace = namespace

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
            zone_id = self.get_device_zone(device_info['device'])
            ips = device_info.get('fixed_ips', [])
            for ip in ips:
                net = netaddr.IPNetwork(ip)
                if str(net.version) not in ethertype:
                    continue
                ip_cmd = [str(net.ip), '-w', zone_id]
                if remote_ip and str(
                        netaddr.IPNetwork(remote_ip).version) in ethertype:
                    ip_cmd.extend(['-s', str(remote_ip)])
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
