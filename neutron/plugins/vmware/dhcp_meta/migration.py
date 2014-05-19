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

from neutron.common import constants as const
from neutron.common import exceptions as n_exc
from neutron.extensions import external_net
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.common import exceptions as p_exc
from neutron.plugins.vmware.dhcp_meta import nsx
from neutron.plugins.vmware.dhcp_meta import rpc

LOG = logging.getLogger(__name__)


class DhcpMetadataBuilder(object):

    def __init__(self, plugin, agent_notifier):
        self.plugin = plugin
        self.notifier = agent_notifier

    def dhcp_agent_get_all(self, context, network_id):
        """Return the agents managing the network."""
        return self.plugin.list_dhcp_agents_hosting_network(
            context, network_id)['agents']

    def dhcp_port_get_all(self, context, network_id):
        """Return the dhcp ports allocated for the network."""
        filters = {
            'network_id': [network_id],
            'device_owner': [const.DEVICE_OWNER_DHCP]
        }
        return self.plugin.get_ports(context, filters=filters)

    def router_id_get(self, context, subnet=None):
        """Return the router and interface used for the subnet."""
        if not subnet:
            return
        network_id = subnet['network_id']
        filters = {
            'network_id': [network_id],
            'device_owner': [const.DEVICE_OWNER_ROUTER_INTF]
        }
        ports = self.plugin.get_ports(context, filters=filters)
        for port in ports:
            if port['fixed_ips'][0]['subnet_id'] == subnet['id']:
                return port['device_id']

    def metadata_deallocate(self, context, router_id, subnet_id):
        """Deallocate metadata services for the subnet."""
        interface = {'subnet_id': subnet_id}
        self.plugin.remove_router_interface(context, router_id, interface)

    def metadata_allocate(self, context, router_id, subnet_id):
        """Allocate metadata resources for the subnet via the router."""
        interface = {'subnet_id': subnet_id}
        self.plugin.add_router_interface(context, router_id, interface)

    def dhcp_deallocate(self, context, network_id, agents, ports):
        """Deallocate dhcp resources for the network."""
        for agent in agents:
            self.plugin.remove_network_from_dhcp_agent(
                context, agent['id'], network_id)
        for port in ports:
            try:
                self.plugin.delete_port(context, port['id'])
            except n_exc.PortNotFound:
                LOG.error(_('Port %s is already gone'), port['id'])

    def dhcp_allocate(self, context, network_id, subnet):
        """Allocate dhcp resources for the subnet."""
        # Create LSN resources
        network_data = {'id': network_id}
        nsx.handle_network_dhcp_access(self.plugin, context,
                                       network_data, 'create_network')
        if subnet:
            subnet_data = {'subnet': subnet}
            self.notifier.notify(context, subnet_data, 'subnet.create.end')
            # Get DHCP host and metadata entries created for the LSN
            port = {
                'network_id': network_id,
                'fixed_ips': [{'subnet_id': subnet['id']}]
            }
            self.notifier.notify(context, {'port': port}, 'port.update.end')


class MigrationManager(object):

    def __init__(self, plugin, lsn_manager, agent_notifier):
        self.plugin = plugin
        self.manager = lsn_manager
        self.builder = DhcpMetadataBuilder(plugin, agent_notifier)

    def validate(self, context, network_id):
        """Validate and return subnet's dhcp info for migration."""
        network = self.plugin.get_network(context, network_id)

        if self.manager.lsn_exists(context, network_id):
            reason = _("LSN already exist")
            raise p_exc.LsnMigrationConflict(net_id=network_id, reason=reason)

        if network[external_net.EXTERNAL]:
            reason = _("Cannot migrate an external network")
            raise n_exc.BadRequest(resource='network', msg=reason)

        filters = {'network_id': [network_id]}
        subnets = self.plugin.get_subnets(context, filters=filters)
        count = len(subnets)
        if count == 0:
            return None
        elif count == 1 and subnets[0]['cidr'] == rpc.METADATA_SUBNET_CIDR:
            reason = _("Cannot migrate a 'metadata' network")
            raise n_exc.BadRequest(resource='network', msg=reason)
        elif count > 1:
            reason = _("Unable to support multiple subnets per network")
            raise p_exc.LsnMigrationConflict(net_id=network_id, reason=reason)
        else:
            return subnets[0]

    def migrate(self, context, network_id, subnet=None):
        """Migrate subnet resources to LSN."""
        router_id = self.builder.router_id_get(context, subnet)
        if router_id and subnet:
            # Deallocate resources taken for the router, if any
            self.builder.metadata_deallocate(context, router_id, subnet['id'])
        if subnet:
            # Deallocate reources taken for the agent, if any
            agents = self.builder.dhcp_agent_get_all(context, network_id)
            ports = self.builder.dhcp_port_get_all(context, network_id)
            self.builder.dhcp_deallocate(context, network_id, agents, ports)
        # (re)create the configuration for LSN
        self.builder.dhcp_allocate(context, network_id, subnet)
        if router_id and subnet:
            # Allocate resources taken for the router, if any
            self.builder.metadata_allocate(context, router_id, subnet['id'])

    def report(self, context, network_id, subnet_id=None):
        """Return a report of the dhcp and metadata resources in use."""
        if subnet_id:
            lsn_id, lsn_port_id = self.manager.lsn_port_get(
                context, network_id, subnet_id, raise_on_err=False)
        else:
            filters = {'network_id': [network_id]}
            subnets = self.plugin.get_subnets(context, filters=filters)
            if subnets:
                lsn_id, lsn_port_id = self.manager.lsn_port_get(
                    context, network_id, subnets[0]['id'], raise_on_err=False)
            else:
                lsn_id = self.manager.lsn_get(context, network_id,
                                              raise_on_err=False)
                lsn_port_id = None
        if lsn_id:
            ports = [lsn_port_id] if lsn_port_id else []
            report = {
                'type': 'lsn',
                'services': [lsn_id],
                'ports': ports
            }
        else:
            agents = self.builder.dhcp_agent_get_all(context, network_id)
            ports = self.builder.dhcp_port_get_all(context, network_id)
            report = {
                'type': 'agent',
                'services': [a['id'] for a in agents],
                'ports': [p['id'] for p in ports]
            }
        return report
