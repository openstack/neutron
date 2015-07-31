# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
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

import random
import testscenarios

from neutron import context
from neutron.scheduler import l3_agent_scheduler
from neutron.services.l3_router import l3_router_plugin
from neutron.tests.common import helpers
from neutron.tests.unit.db import test_db_base_plugin_v2

# Required to generate tests from scenarios. Not compatible with nose.
load_tests = testscenarios.load_tests_apply_scenarios


class L3SchedulerBaseTest(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    """Base class for functional test of L3 schedulers.
       Provides basic setup and utility functions.
    """

    def setUp(self):
        super(L3SchedulerBaseTest, self).setUp()

        self.l3_plugin = l3_router_plugin.L3RouterPlugin()
        self.adminContext = context.get_admin_context()
        self.adminContext.tenant_id = '_func_test_tenant_'

    def _create_l3_agent(self, host, context, agent_mode='legacy', plugin=None,
                         state=True):
        agent = helpers.register_l3_agent(host, agent_mode)
        helpers.set_agent_admin_state(agent.id, state)
        return agent

    def _create_router(self, name):
        router = {'name': name, 'admin_state_up': True}
        return self.l3_plugin.create_router(
            self.adminContext, {'router': router})

    def _create_legacy_agents(self, agent_count, down_agent_count):
        # Creates legacy l3 agents and sets admin state based on
        #  down agent count.
        self.hosts = ['host-%s' % i for i in range(agent_count)]
        self.l3_agents = [self._create_l3_agent(self.hosts[i],
               self.adminContext, 'legacy', self.l3_plugin,
               (i >= down_agent_count)) for i in range(agent_count)]

    def _create_routers(self, scheduled_router_count,
                        expected_scheduled_router_count):
        routers = []
        if (scheduled_router_count + expected_scheduled_router_count):
            for i in range(scheduled_router_count +
                           expected_scheduled_router_count):
                router = self._create_router('schd_rtr' + str(i))
                routers.append(router)
        else:
            # create at least one router to test scheduling
            routers.append(self._create_router('schd_rtr0'))

        return routers

    def _pre_scheduler_routers(self, scheduler, count):
        hosting_agents = []
        # schedule routers before calling schedule:
        for i in range(count):
            router = self.routers[i]
            agent = random.choice(self.l3_agents)
            scheduler.bind_router(self.adminContext, router['id'], agent)
            hosting_agents.append(agent)
        return hosting_agents

    def _test_auto_schedule(self, expected_count):
        router_ids = [rtr['id'] for rtr in self.routers]

        did_it_schedule = False

        # Try scheduling on each host
        for host in self.hosts:
            did_it_schedule = self.scheduler.auto_schedule_routers(
                self.l3_plugin,
                self.adminContext,
                host,
                router_ids)
            if did_it_schedule:
                break

        if expected_count:
            self.assertTrue(did_it_schedule, 'Failed to schedule agent')
        else:
            self.assertFalse(did_it_schedule, 'Agent scheduled, not expected')


class L3ChanceSchedulerTestCase(L3SchedulerBaseTest):

    """Test various scenarios for chance scheduler.

        agent_count
            Number of l3 agents (also number of hosts).

        down_agent_count
            Number of l3 agents which are down.

        scheduled_router_count
            Number of routers that have been previously scheduled.

        expected_scheduled_router_count
            Number of newly scheduled routers.
    """

    scenarios = [
        ('No routers scheduled if no agents are present',
         dict(agent_count=0,
              down_agent_count=0,
              scheduled_router_count=0,
              expected_scheduled_router_count=0)),

        ('No routers scheduled if it is already hosted',
         dict(agent_count=1,
              down_agent_count=0,
              scheduled_router_count=1,
              expected_scheduled_router_count=0)),

        ('No routers scheduled if all agents are down',
         dict(agent_count=2,
              down_agent_count=2,
              scheduled_router_count=0,
              expected_scheduled_router_count=0)),

        ('Router scheduled to the agent if router is not yet hosted',
         dict(agent_count=1,
              down_agent_count=0,
              scheduled_router_count=0,
              expected_scheduled_router_count=1)),

        ('Router scheduled to the agent even if it already hosts a router',
         dict(agent_count=1,
              down_agent_count=0,
              scheduled_router_count=1,
              expected_scheduled_router_count=1)),
    ]

    def setUp(self):
        super(L3ChanceSchedulerTestCase, self).setUp()
        self._create_legacy_agents(self.agent_count, self.down_agent_count)
        self.routers = self._create_routers(self.scheduled_router_count,
                             self.expected_scheduled_router_count)
        self.scheduler = l3_agent_scheduler.ChanceScheduler()

    def test_chance_schedule_router(self):
        # Pre schedule routers
        self._pre_scheduler_routers(self.scheduler,
                                    self.scheduled_router_count)
        # schedule:
        actual_scheduled_agent = self.scheduler.schedule(
            self.l3_plugin, self.adminContext, self.routers[-1]['id'])

        if self.expected_scheduled_router_count:
            self.assertIsNotNone(actual_scheduled_agent,
                                 message='Failed to schedule agent')
        else:
            self.assertIsNone(actual_scheduled_agent,
                              message='Agent scheduled but not expected')

    def test_auto_schedule_routers(self):
        # Pre schedule routers
        self._pre_scheduler_routers(self.scheduler,
                                    self.scheduled_router_count)
        # The test
        self._test_auto_schedule(self.expected_scheduled_router_count)


class L3LeastRoutersSchedulerTestCase(L3SchedulerBaseTest):

    """Test various scenarios for least router scheduler.

        agent_count
            Number of l3 agents (also number of hosts).

        down_agent_count
            Number of l3 agents which are down.

        scheduled_router_count
            Number of routers that have been previously scheduled

        expected_scheduled_router_count
            Number of newly scheduled routers
    """

    scenarios = [
        ('No routers scheduled if no agents are present',
         dict(agent_count=0,
              down_agent_count=0,
              scheduled_router_count=0,
              expected_scheduled_router_count=0)),

        ('No routers scheduled if it is already hosted',
         dict(agent_count=1,
              down_agent_count=0,
              scheduled_router_count=1,
              expected_scheduled_router_count=1)),

        ('No routers scheduled if all agents are down',
         dict(agent_count=2,
              down_agent_count=2,
              scheduled_router_count=0,
              expected_scheduled_router_count=0)),

        ('Router scheduled to the agent if router is not yet hosted',
         dict(agent_count=1,
              down_agent_count=0,
              scheduled_router_count=0,
              expected_scheduled_router_count=1)),

        ('Router scheduled to the agent even if it already hosts a router',
         dict(agent_count=1,
              down_agent_count=0,
              scheduled_router_count=1,
              expected_scheduled_router_count=1)),

        ('Router is scheduled to agent hosting least routers',
         dict(agent_count=2,
              down_agent_count=0,
              scheduled_router_count=1,
              expected_scheduled_router_count=1)),
    ]

    def setUp(self):
        super(L3LeastRoutersSchedulerTestCase, self).setUp()
        self._create_legacy_agents(self.agent_count, self.down_agent_count)
        self.routers = self._create_routers(self.scheduled_router_count,
                             self.expected_scheduled_router_count)
        self.scheduler = l3_agent_scheduler.LeastRoutersScheduler()

    def test_least_routers_schedule(self):
        # Pre schedule routers
        hosting_agents = self._pre_scheduler_routers(self.scheduler,
                                    self.scheduled_router_count)

        actual_scheduled_agent = self.scheduler.schedule(
            self.l3_plugin, self.adminContext, self.routers[-1]['id'])

        if self.expected_scheduled_router_count:
            # For case where there is just one agent:
            if self.agent_count == 1:
                self.assertEqual(actual_scheduled_agent.id,
                                 self.l3_agents[0].id)
            else:
                self.assertNotIn(actual_scheduled_agent.id,
                               [x.id for x in hosting_agents],
                               message='The expected agent was not scheduled')
        else:
            self.assertIsNone(actual_scheduled_agent,
                              message='Expected no agent to be scheduled,'
                                      ' but it got scheduled')

    def test_auto_schedule_routers(self):
        # Pre schedule routers
        self._pre_scheduler_routers(self.scheduler,
                                    self.scheduled_router_count)
        # The test
        self._test_auto_schedule(self.expected_scheduled_router_count)
