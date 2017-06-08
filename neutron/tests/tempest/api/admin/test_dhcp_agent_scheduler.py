# Copyright 2013 IBM Corp.
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

from neutron_lib import constants
from tempest.lib import decorators

from neutron.common import utils
from neutron.tests.tempest.api import base


class DHCPAgentSchedulersTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['dhcp_agent_scheduler']

    @classmethod
    def resource_setup(cls):
        super(DHCPAgentSchedulersTestJSON, cls).resource_setup()
        # Create a network and make sure it will be hosted by a
        # dhcp agent: this is done by creating a regular port
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.cidr = cls.subnet['cidr']
        cls.port = cls.create_port(cls.network)

    @decorators.idempotent_id('f164801e-1dd8-4b8b-b5d3-cc3ac77cfaa5')
    def test_dhcp_port_status_active(self):

        def dhcp_port_active():
            for p in self.client.list_ports(
                    network_id=self.network['id'])['ports']:
                if (p['device_owner'] == constants.DEVICE_OWNER_DHCP and
                        p['status'] == constants.PORT_STATUS_ACTIVE):
                    return True
            return False
        utils.wait_until_true(dhcp_port_active)

    @decorators.idempotent_id('5032b1fe-eb42-4a64-8f3b-6e189d8b5c7d')
    def test_list_dhcp_agent_hosting_network(self):
        self.admin_client.list_dhcp_agent_hosting_network(
            self.network['id'])

    @decorators.idempotent_id('30c48f98-e45d-4ffb-841c-b8aad57c7587')
    def test_list_networks_hosted_by_one_dhcp(self):
        body = self.admin_client.list_dhcp_agent_hosting_network(
            self.network['id'])
        agents = body['agents']
        self.assertIsNotNone(agents)
        agent = agents[0]
        self.assertTrue(self._check_network_in_dhcp_agent(
            self.network['id'], agent))

    def _check_network_in_dhcp_agent(self, network_id, agent):
        network_ids = []
        body = self.admin_client.list_networks_hosted_by_one_dhcp_agent(
            agent['id'])
        networks = body['networks']
        for network in networks:
            network_ids.append(network['id'])
        return network_id in network_ids

    @decorators.idempotent_id('a0856713-6549-470c-a656-e97c8df9a14d')
    def test_add_remove_network_from_dhcp_agent(self):
        # The agent is now bound to the network, we can free the port
        self.client.delete_port(self.port['id'])
        self.ports.remove(self.port)
        agent = dict()
        agent['agent_type'] = None
        body = self.admin_client.list_agents()
        agents = body['agents']
        for a in agents:
            if a['agent_type'] == 'DHCP agent':
                agent = a
                break
        self.assertEqual(agent['agent_type'], 'DHCP agent', 'Could not find '
                         'DHCP agent in agent list though dhcp_agent_scheduler'
                         ' is enabled.')
        network = self.create_network()
        network_id = network['id']
        if self._check_network_in_dhcp_agent(network_id, agent):
            self._remove_network_from_dhcp_agent(network_id, agent)
            self._add_dhcp_agent_to_network(network_id, agent)
        else:
            self._add_dhcp_agent_to_network(network_id, agent)
            self._remove_network_from_dhcp_agent(network_id, agent)

    def _remove_network_from_dhcp_agent(self, network_id, agent):
        self.admin_client.remove_network_from_dhcp_agent(
            agent_id=agent['id'],
            network_id=network_id)
        self.assertFalse(self._check_network_in_dhcp_agent(
            network_id, agent))

    def _add_dhcp_agent_to_network(self, network_id, agent):
        self.admin_client.add_dhcp_agent_to_network(agent['id'],
                                                    network_id)
        self.assertTrue(self._check_network_in_dhcp_agent(
            network_id, agent))
