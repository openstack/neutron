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
# from securitygroups_rpc.py.


class SecurityGroupServerRpcCallback(n_rpc.RpcCallback):
    """Callback for SecurityGroup agent RPC in plugin implementations.

    Subclass which inherits this class must implement get_port_from_device().
    """

    # API version history:
    #   1.1 - Initial version

    # NOTE: RPC_API_VERSION must not be overridden in subclasses
    # to keep RPC API version consistent across plugins.
    RPC_API_VERSION = '1.1'

    @property
    def plugin(self):
        return manager.NeutronManager.get_plugin()

    def security_group_rules_for_devices(self, context, **kwargs):
        """Callback method to return security group rules for each port.

        also convert remote_group_id rule
        to source_ip_prefix and dest_ip_prefix rule

        :params devices: list of devices
        :returns: port correspond to the devices with security group rules
        """
        devices = kwargs.get('devices')

        ports = {}
        for device in devices:
            port = self.plugin.get_port_from_device(device)
            if not port:
                continue
            if port['device_owner'].startswith('network:'):
                continue
            ports[port['id']] = port
        return self.plugin.security_group_rules_for_ports(context, ports)
