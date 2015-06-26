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

from neutron.tests.api import base
from neutron.tests.tempest.common import tempest_fixtures as fixtures
from neutron.tests.tempest import test


class AgentManagementTestJSON(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(AgentManagementTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('agent', 'network'):
            msg = "agent extension not enabled."
            raise cls.skipException(msg)
        body = cls.admin_client.list_agents()
        agents = body['agents']
        cls.agent = agents[0]  # don't modify this agent
        cls.dyn_agent = agents[1]

    @test.attr(type='smoke')
    @test.idempotent_id('9c80f04d-11f3-44a4-8738-ed2f879b0ff4')
    def test_list_agent(self):
        body = self.admin_client.list_agents()
        agents = body['agents']
        # Hearthbeats must be excluded from comparison
        self.agent.pop('heartbeat_timestamp', None)
        self.agent.pop('configurations', None)
        for agent in agents:
            agent.pop('heartbeat_timestamp', None)
            agent.pop('configurations', None)
        self.assertIn(self.agent, agents)

    @test.attr(type=['smoke'])
    @test.idempotent_id('e335be47-b9a1-46fd-be30-0874c0b751e6')
    def test_list_agents_non_admin(self):
        body = self.client.list_agents()
        self.assertEqual(len(body["agents"]), 0)

    @test.attr(type='smoke')
    @test.idempotent_id('869bc8e8-0fda-4a30-9b71-f8a7cf58ca9f')
    def test_show_agent(self):
        body = self.admin_client.show_agent(self.agent['id'])
        agent = body['agent']
        self.assertEqual(agent['id'], self.agent['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('371dfc5b-55b9-4cb5-ac82-c40eadaac941')
    def test_update_agent_status(self):
        origin_status = self.agent['admin_state_up']
        # Try to update the 'admin_state_up' to the original
        # one to avoid the negative effect.
        agent_status = {'admin_state_up': origin_status}
        body = self.admin_client.update_agent(agent_id=self.agent['id'],
                                              agent_info=agent_status)
        updated_status = body['agent']['admin_state_up']
        self.assertEqual(origin_status, updated_status)

    @test.attr(type='smoke')
    @test.idempotent_id('68a94a14-1243-46e6-83bf-157627e31556')
    def test_update_agent_description(self):
        self.useFixture(fixtures.LockFixture('agent_description'))
        description = 'description for update agent.'
        agent_description = {'description': description}
        body = self.admin_client.update_agent(agent_id=self.dyn_agent['id'],
                                              agent_info=agent_description)
        self.addCleanup(self._restore_agent)
        updated_description = body['agent']['description']
        self.assertEqual(updated_description, description)

    def _restore_agent(self):
        """
        Restore the agent description after update test.
        """
        description = self.dyn_agent['description']
        origin_agent = {'description': description}
        self.admin_client.update_agent(agent_id=self.dyn_agent['id'],
                                       agent_info=origin_agent)
