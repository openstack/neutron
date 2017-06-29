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

from neutron.tests.tempest.common import tempest_fixtures
from tempest.lib import decorators

from neutron.tests.tempest.api import base


class AgentManagementTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['agent']

    @classmethod
    def resource_setup(cls):
        super(AgentManagementTestJSON, cls).resource_setup()
        body = cls.admin_client.list_agents()
        agents = body['agents']
        cls.agent = agents[0]  # don't modify this agent

    @decorators.idempotent_id('9c80f04d-11f3-44a4-8738-ed2f879b0ff4')
    def test_list_agent(self):
        body = self.admin_client.list_agents()
        agents = body['agents']
        # Heartbeats must be excluded from comparison
        self.agent.pop('heartbeat_timestamp', None)
        self.agent.pop('configurations', None)
        for agent in agents:
            agent.pop('heartbeat_timestamp', None)
            agent.pop('configurations', None)
        self.assertIn(self.agent, agents)

    @decorators.idempotent_id('e335be47-b9a1-46fd-be30-0874c0b751e6')
    def test_list_agents_non_admin(self):
        body = self.client.list_agents()
        self.assertEqual(len(body["agents"]), 0)

    @decorators.idempotent_id('869bc8e8-0fda-4a30-9b71-f8a7cf58ca9f')
    def test_show_agent(self):
        body = self.admin_client.show_agent(self.agent['id'])
        agent = body['agent']
        self.assertEqual(agent['id'], self.agent['id'])

    @decorators.idempotent_id('371dfc5b-55b9-4cb5-ac82-c40eadaac941')
    def test_update_agent_status(self):
        origin_status = self.agent['admin_state_up']
        # Try to update the 'admin_state_up' to the original
        # one to avoid the negative effect.
        agent_status = {'admin_state_up': origin_status}
        body = self.admin_client.update_agent(agent_id=self.agent['id'],
                                              agent_info=agent_status)
        updated_status = body['agent']['admin_state_up']
        self.assertEqual(origin_status, updated_status)

    @decorators.idempotent_id('68a94a14-1243-46e6-83bf-157627e31556')
    def test_update_agent_description(self):
        agents = self.admin_client.list_agents()['agents']
        try:
            dyn_agent = agents[1]
        except IndexError:
            raise self.skipException("This test requires at least two agents.")

        self.useFixture(tempest_fixtures.LockFixture('agent_description'))
        description = 'description for update agent.'
        agent_description = {'description': description}
        body = self.admin_client.update_agent(agent_id=dyn_agent['id'],
                                              agent_info=agent_description)
        self.addCleanup(self._restore_agent, dyn_agent)
        updated_description = body['agent']['description']
        self.assertEqual(updated_description, description)

    def _restore_agent(self, dyn_agent):
        """
        Restore the agent description after update test.
        """
        description = dyn_agent['description']
        origin_agent = {'description': description}
        self.admin_client.update_agent(agent_id=dyn_agent['id'],
                                       agent_info=origin_agent)
