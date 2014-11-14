# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.common import rpc as n_rpc
from neutron import manager


# TODO(amotoki): Move security group RPC API and agent callback
# from neutron/agent/securitygroups_rpc.py.


class SecurityGroupServerRpcCallback(n_rpc.RpcCallback):
    """Callback for SecurityGroup agent RPC in plugin implementations."""

    # API version history:
    #   1.1 - Initial version
    #   1.2 - security_group_info_for_devices introduced as an optimization

    # NOTE: RPC_API_VERSION must not be overridden in subclasses
    # to keep RPC API version consistent across plugins.
    RPC_API_VERSION = '1.2'

    @property
    def plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_devices_info(self, devices):
        return dict(
            (port['id'], port)
            for port in self.plugin.get_ports_from_devices(devices)
            if port and not port['device_owner'].startswith('network:')
        )

    def security_group_rules_for_devices(self, context, **kwargs):
        """Callback method to return security group rules for each port.

        also convert remote_group_id rule
        to source_ip_prefix and dest_ip_prefix rule

        :params devices: list of devices
        :returns: port correspond to the devices with security group rules
        """
        devices_info = kwargs.get('devices')
        ports = self._get_devices_info(devices_info)
        return self.plugin.security_group_rules_for_ports(context, ports)

    def security_group_info_for_devices(self, context, **kwargs):
        """Return security group information for requested devices.

        :params devices: list of devices
        :returns:
        sg_info{
          'security_groups': {sg_id: [rule1, rule2]}
          'sg_member_ips': {sg_id: {'IPv4': [], 'IPv6': []}}
          'devices': {device_id: {device_info}}
        }
        """
        devices_info = kwargs.get('devices')
        ports = self._get_devices_info(devices_info)
        return self.plugin.security_group_info_for_ports(context, ports)
