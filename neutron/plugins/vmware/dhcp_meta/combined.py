# Copyright 2014 VMware, Inc.
#
# All Rights Reserved
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
#

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import constants as const
from neutron.common import topics
from neutron.plugins.vmware.dhcp_meta import nsx as nsx_svc
from neutron.plugins.vmware.dhcp_meta import rpc as nsx_rpc


class DhcpAgentNotifyAPI(dhcp_rpc_agent_api.DhcpAgentNotifyAPI):

    def __init__(self, plugin, manager):
        super(DhcpAgentNotifyAPI, self).__init__(topic=topics.DHCP_AGENT)
        self.agentless_notifier = nsx_svc.DhcpAgentNotifyAPI(plugin, manager)

    def notify(self, context, data, methodname):
        [resource, action, _e] = methodname.split('.')
        lsn_manager = self.agentless_notifier.plugin.lsn_manager
        plugin = self.agentless_notifier.plugin
        if resource == 'network':
            net_id = data['network']['id']
        elif resource in ['port', 'subnet']:
            net_id = data[resource]['network_id']
        else:
            # no valid resource
            return
        lsn_exists = lsn_manager.lsn_exists(context, net_id)
        treat_dhcp_owner_specially = False
        if lsn_exists:
            # if lsn exists, the network is one created with the new model
            if (resource == 'subnet' and action == 'create' and
                const.DEVICE_OWNER_DHCP not in plugin.port_special_owners):
                # network/subnet provisioned in the new model have a plain
                # nsx lswitch port, no vif attachment
                    plugin.port_special_owners.append(const.DEVICE_OWNER_DHCP)
                    treat_dhcp_owner_specially = True
            if (resource == 'port' and action == 'update' or
                resource == 'subnet'):
                self.agentless_notifier.notify(context, data, methodname)
        elif not lsn_exists and resource in ['port', 'subnet']:
            # call notifier for the agent-based mode
            super(DhcpAgentNotifyAPI, self).notify(context, data, methodname)
        if treat_dhcp_owner_specially:
            # if subnets belong to networks created with the old model
            # dhcp port does not need to be special cased, so put things
            # back, since they were modified
            plugin.port_special_owners.remove(const.DEVICE_OWNER_DHCP)


def handle_network_dhcp_access(plugin, context, network, action):
    nsx_svc.handle_network_dhcp_access(plugin, context, network, action)


def handle_port_dhcp_access(plugin, context, port, action):
    if plugin.lsn_manager.lsn_exists(context, port['network_id']):
        nsx_svc.handle_port_dhcp_access(plugin, context, port, action)
    else:
        nsx_rpc.handle_port_dhcp_access(plugin, context, port, action)


def handle_port_metadata_access(plugin, context, port, is_delete=False):
    if plugin.lsn_manager.lsn_exists(context, port['network_id']):
        nsx_svc.handle_port_metadata_access(plugin, context, port, is_delete)
    else:
        nsx_rpc.handle_port_metadata_access(plugin, context, port, is_delete)


def handle_router_metadata_access(plugin, context, router_id, interface=None):
    if interface:
        subnet = plugin.get_subnet(context, interface['subnet_id'])
        network_id = subnet['network_id']
        if plugin.lsn_manager.lsn_exists(context, network_id):
            nsx_svc.handle_router_metadata_access(
                plugin, context, router_id, interface)
        else:
            nsx_rpc.handle_router_metadata_access(
                plugin, context, router_id, interface)
    else:
        nsx_rpc.handle_router_metadata_access(
            plugin, context, router_id, interface)
