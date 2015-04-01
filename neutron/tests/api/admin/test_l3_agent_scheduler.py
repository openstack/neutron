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

from tempest_lib.common.utils import data_utils

from neutron.tests.api import base
from neutron.tests.tempest import test


class L3AgentSchedulerTestJSON(base.BaseAdminNetworkTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        List routers that the given L3 agent is hosting.
        List L3 agents hosting the given router.
        Add and Remove Router to L3 agent

    v2.0 of the Neutron API is assumed.

    The l3_agent_scheduler extension is required for these tests.
    """

    @classmethod
    def resource_setup(cls):
        super(L3AgentSchedulerTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('l3_agent_scheduler', 'network'):
            msg = "L3 Agent Scheduler Extension not enabled."
            raise cls.skipException(msg)
        # Trying to get agent details for L3 Agent
        body = cls.admin_client.list_agents()
        agents = body['agents']
        for agent in agents:
            if agent['agent_type'] == 'L3 agent':
                cls.agent = agent
                break
        else:
            msg = "L3 Agent not found"
            raise cls.skipException(msg)

    @test.attr(type='smoke')
    @test.idempotent_id('b7ce6e89-e837-4ded-9b78-9ed3c9c6a45a')
    def test_list_routers_on_l3_agent(self):
        self.admin_client.list_routers_on_l3_agent(self.agent['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('9464e5e7-8625-49c3-8fd1-89c52be59d66')
    def test_add_list_remove_router_on_l3_agent(self):
        l3_agent_ids = list()
        name = data_utils.rand_name('router1-')
        router = self.client.create_router(name)
        self.addCleanup(self.client.delete_router, router['router']['id'])
        self.admin_client.add_router_to_l3_agent(
            self.agent['id'],
            router['router']['id'])
        body = self.admin_client.list_l3_agents_hosting_router(
            router['router']['id'])
        for agent in body['agents']:
            l3_agent_ids.append(agent['id'])
            self.assertIn('agent_type', agent)
            self.assertEqual('L3 agent', agent['agent_type'])
        self.assertIn(self.agent['id'], l3_agent_ids)
        del l3_agent_ids[:]
        body = self.admin_client.remove_router_from_l3_agent(
            self.agent['id'],
            router['router']['id'])
        # NOTE(afazekas): The deletion not asserted, because neutron
        # is not forbidden to reschedule the router to the same agent
