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

import collections
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
        router = {'name': name, 'admin_state_up': True,
                  'tenant_id': self.adminContext.tenant_id}
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


class L3AZSchedulerBaseTest(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        core_plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        super(L3AZSchedulerBaseTest, self).setUp(plugin=core_plugin)

        self.l3_plugin = l3_router_plugin.L3RouterPlugin()
        self.adminContext = context.get_admin_context()
        self.adminContext.tenant_id = '_func_test_tenant_'

    def _create_l3_agent(self, host, context, agent_mode='legacy', plugin=None,
                         state=True, az='nova'):
        agent = helpers.register_l3_agent(host, agent_mode, az=az)
        helpers.set_agent_admin_state(agent.id, state)
        return agent

    def _create_legacy_agents(self, agent_count, down_agent_count, az):
        # Creates legacy l3 agents and sets admin state based on
        #  down agent count.
        hosts = ['%s-host-%s' % (az, i) for i in range(agent_count)]
        l3_agents = [
            self._create_l3_agent(hosts[i], self.adminContext, 'legacy',
                                  self.l3_plugin, (i >= down_agent_count),
                                  az=az)
            for i in range(agent_count)]
        return l3_agents

    def _create_router(self, az_hints, ha):
        router = {'name': 'router1', 'admin_state_up': True,
                  'availability_zone_hints': az_hints,
                  'tenant_id': self._tenant_id}
        if ha:
            router['ha'] = True
        return self.l3_plugin.create_router(
            self.adminContext, {'router': router})


class L3AZLeastRoutersSchedulerTestCase(L3AZSchedulerBaseTest):

    """Test various scenarios for AZ router scheduler.

        az_count
            Number of AZs.

        router_az_hints
            Number of AZs in availability_zone_hints of the router.

        agent_count[each az]
            Number of l3 agents (also number of hosts).

        max_l3_agents_per_router
            Maximum number of agents on which a router will be scheduled.
            0 means test for regular router.

        min_l3_agents_per_router
            Minimum number of agents on which a router will be scheduled.
            N/A for regular router test.

        down_agent_count[each az]
            Number of l3 agents which are down.

        expected_scheduled_agent_count[each az]
            Number of newly scheduled l3 agents.
    """

    scenarios = [
        ('Regular router, Scheduled specified AZ',
         dict(az_count=2,
              router_az_hints=1,
              agent_count=[1, 1],
              max_l3_agents_per_router=0,
              min_l3_agents_per_router=0,
              down_agent_count=[0, 0],
              expected_scheduled_agent_count=[1, 0])),

        ('HA router, Scheduled specified AZs',
         dict(az_count=3,
              router_az_hints=2,
              agent_count=[1, 1, 1],
              max_l3_agents_per_router=2,
              min_l3_agents_per_router=2,
              down_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[1, 1, 0])),

        ('HA router, max_l3_agents_per_routers > az_hints',
         dict(az_count=2,
              router_az_hints=2,
              agent_count=[2, 1],
              max_l3_agents_per_router=3,
              min_l3_agents_per_router=2,
              down_agent_count=[0, 0],
              expected_scheduled_agent_count=[2, 1])),

        ('HA router, not enough agents',
         dict(az_count=3,
              router_az_hints=2,
              agent_count=[2, 2, 2],
              max_l3_agents_per_router=3,
              min_l3_agents_per_router=2,
              down_agent_count=[1, 1, 0],
              expected_scheduled_agent_count=[1, 1, 0])),
    ]

    def test_schedule_router(self):
        scheduler = l3_agent_scheduler.AZLeastRoutersScheduler()
        ha = False
        if self.max_l3_agents_per_router:
            self.config(max_l3_agents_per_router=self.max_l3_agents_per_router)
            self.config(min_l3_agents_per_router=self.min_l3_agents_per_router)
            ha = True

        # create l3 agents
        for i in range(self.az_count):
            az = 'az%s' % i
            self._create_legacy_agents(self.agent_count[i],
                                       self.down_agent_count[i], az)

        # create router.
        # note that ha-router needs enough agents beforehand.
        az_hints = ['az%s' % i for i in range(self.router_az_hints)]
        router = self._create_router(az_hints, ha)

        scheduler.schedule(self.l3_plugin, self.adminContext, router['id'])
        # schedule returns only one agent. so get all agents scheduled.
        scheduled_agents = self.l3_plugin.get_l3_agents_hosting_routers(
            self.adminContext, [router['id']])

        scheduled_azs = collections.defaultdict(int)
        for agent in scheduled_agents:
            scheduled_azs[agent['availability_zone']] += 1

        for i in range(self.az_count):
            self.assertEqual(self.expected_scheduled_agent_count[i],
                             scheduled_azs.get('az%s' % i, 0))


class L3AZAutoScheduleTestCaseBase(L3AZSchedulerBaseTest):

    """Test various scenarios for AZ router scheduler.

        az_count
            Number of AZs.

        router_az_hints
            Number of AZs in availability_zone_hints of the router.

        agent_az
            AZ of newly activated l3 agent.

        agent_count[each az]
            Number of l3 agents (also number of hosts).

        max_l3_agents_per_router
            Maximum number of agents on which a router will be scheduled.
            0 means test for regular router.

        min_l3_agents_per_router
            Minimum number of agents on which a router will be scheduled.
            N/A for regular router test.

        down_agent_count[each az]
            Number of l3 agents which are down.

        scheduled_agent_count[each az]
            Number of l3 agents that have been previously scheduled

        expected_scheduled_agent_count[each az]
            Number of newly scheduled l3 agents
    """

    scenarios = [
        ('Regular router, not scheduled, agent in specified AZ activated',
         dict(az_count=2,
              router_az_hints=1,
              agent_az='az0',
              agent_count=[1, 1],
              max_l3_agents_per_router=0,
              min_l3_agents_per_router=0,
              down_agent_count=[1, 1],
              scheduled_agent_count=[0, 0],
              expected_scheduled_agent_count=[1, 0])),

        ('Regular router, not scheduled, agent not in specified AZ activated',
         dict(az_count=2,
              router_az_hints=1,
              agent_az='az1',
              agent_count=[1, 1],
              max_l3_agents_per_router=0,
              min_l3_agents_per_router=0,
              down_agent_count=[1, 1],
              scheduled_agent_count=[0, 0],
              expected_scheduled_agent_count=[0, 0])),

        ('HA router, not scheduled, agent in specified AZ activated',
         dict(az_count=3,
              router_az_hints=2,
              agent_az='az1',
              agent_count=[1, 1, 1],
              max_l3_agents_per_router=2,
              min_l3_agents_per_router=2,
              down_agent_count=[0, 1, 0],
              scheduled_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[0, 1, 0])),

        ('HA router, not scheduled, agent not in specified AZ activated',
         dict(az_count=3,
              router_az_hints=2,
              agent_az='az2',
              agent_count=[1, 1, 1],
              max_l3_agents_per_router=2,
              min_l3_agents_per_router=2,
              down_agent_count=[0, 0, 1],
              scheduled_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[0, 0, 0])),

        ('HA router, partial scheduled, agent in specified AZ activated',
         dict(az_count=3,
              router_az_hints=2,
              agent_az='az1',
              agent_count=[1, 1, 1],
              max_l3_agents_per_router=2,
              min_l3_agents_per_router=2,
              down_agent_count=[0, 1, 0],
              scheduled_agent_count=[1, 0, 0],
              expected_scheduled_agent_count=[1, 1, 0])),
    ]

    def test_auto_schedule_router(self):
        scheduler = l3_agent_scheduler.AZLeastRoutersScheduler()
        ha = False
        if self.max_l3_agents_per_router:
            self.config(max_l3_agents_per_router=self.max_l3_agents_per_router)
            self.config(min_l3_agents_per_router=self.min_l3_agents_per_router)
            ha = True

        # create l3 agents
        l3_agents = {}
        for i in range(self.az_count):
            az = 'az%s' % i
            l3_agents[az] = self._create_legacy_agents(
                self.agent_count[i], self.down_agent_count[i], az)

        # create router.
        # note that ha-router needs enough agents beforehand.
        az_hints = ['az%s' % i for i in range(self.router_az_hints)]
        router = self._create_router(az_hints, ha)

        # schedule some agents before calling auto schedule
        for i in range(self.az_count):
            az = 'az%s' % i
            for j in range(self.scheduled_agent_count[i]):
                agent = l3_agents[az][j + self.down_agent_count[i]]
                scheduler.bind_router(self.adminContext, router['id'], agent)

        # activate down agent and call auto_schedule_routers
        activate_agent = l3_agents[self.agent_az][0]
        helpers.set_agent_admin_state(activate_agent['id'],
                                      admin_state_up=True)

        scheduler.auto_schedule_routers(self.l3_plugin, self.adminContext,
                                        activate_agent['host'], None)

        scheduled_agents = self.l3_plugin.get_l3_agents_hosting_routers(
            self.adminContext, [router['id']])

        scheduled_azs = collections.defaultdict(int)
        for agent in scheduled_agents:
            scheduled_azs[agent['availability_zone']] += 1

        for i in range(self.az_count):
            self.assertEqual(self.expected_scheduled_agent_count[i],
                             scheduled_azs.get('az%s' % i, 0))
