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

from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils
import testscenarios

from neutron.objects import network as net_obj
from neutron.scheduler import l3_agent_scheduler
from neutron.services.l3_router import l3_router_plugin
from neutron.tests.common import helpers
from neutron.tests.unit.db import test_db_base_plugin_v2

_uuid = uuidutils.generate_uuid

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'

# Required to generate tests from scenarios. Not compatible with nose.
load_tests = testscenarios.load_tests_apply_scenarios


class L3SchedulerBaseTest(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    """Base class for functional test of L3 schedulers.
       Provides basic setup and utility functions.
    """

    def setUp(self):
        super(L3SchedulerBaseTest, self).setUp(PLUGIN_NAME)

        self.l3_plugin = l3_router_plugin.L3RouterPlugin()
        directory.add_plugin(plugin_constants.L3, self.l3_plugin)
        self.adminContext = context.get_admin_context()
        self.adminContext.tenant_id = _uuid()

    def _create_l3_agent(self, host, context, agent_mode='legacy',
                         state=True, ext_net_id=''):
        agent = helpers.register_l3_agent(host, agent_mode,
                                          ext_net_id=ext_net_id)
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
               self.adminContext, 'legacy',
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
            scheduler.bind_router(self.l3_plugin, self.adminContext,
                                  router['id'], agent.id)
            hosting_agents.append(agent)
        return hosting_agents

    def _test_auto_schedule(self, expected_count):
        router_ids = [rtr['id'] for rtr in self.routers]

        hosting_before = self.l3_plugin.get_l3_agents_hosting_routers(
            self.adminContext, router_ids)

        # Try scheduling on each host
        for host in self.hosts:
            self.scheduler.auto_schedule_routers(
                self.l3_plugin,
                self.adminContext,
                host)

        hosting_after = self.l3_plugin.get_l3_agents_hosting_routers(
            self.adminContext, router_ids)

        if expected_count:
            self.assertNotEqual(hosting_before, hosting_after,
                                'Failed to schedule agent')
        else:
            self.assertEqual(hosting_before, hosting_after,
                             'Agent scheduled, not expected')


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
        super(L3AZSchedulerBaseTest, self).setUp(plugin='ml2')

        self.l3_plugin = l3_router_plugin.L3RouterPlugin()
        directory.add_plugin(plugin_constants.L3, self.l3_plugin)
        self.l3_plugin.router_scheduler = None
        directory.add_plugin(plugin_constants.L3, self.l3_plugin)
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
              down_agent_count=[0, 0],
              expected_scheduled_agent_count=[1, 0])),

        ('HA router, Scheduled specified AZs',
         dict(az_count=3,
              router_az_hints=2,
              agent_count=[1, 1, 1],
              max_l3_agents_per_router=2,
              down_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[1, 1, 0])),

        ('HA router, max_l3_agents_per_routers > az_hints',
         dict(az_count=2,
              router_az_hints=2,
              agent_count=[2, 1],
              max_l3_agents_per_router=3,
              down_agent_count=[0, 0],
              expected_scheduled_agent_count=[2, 1])),
    ]

    def setUp(self):
        super(L3AZLeastRoutersSchedulerTestCase, self).setUp()
        self.scheduler = l3_agent_scheduler.AZLeastRoutersScheduler()
        self.l3_plugin.router_scheduler = self.scheduler

    def test_schedule_router(self):
        ha = False
        if self.max_l3_agents_per_router:
            self.config(max_l3_agents_per_router=self.max_l3_agents_per_router)
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

        self.scheduler.schedule(self.l3_plugin, self.adminContext,
                                router['id'])
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
              down_agent_count=[1, 1],
              scheduled_agent_count=[0, 0],
              expected_scheduled_agent_count=[1, 0])),

        ('Regular router, not scheduled, agent not in specified AZ activated',
         dict(az_count=2,
              router_az_hints=1,
              agent_az='az1',
              agent_count=[1, 1],
              max_l3_agents_per_router=0,
              down_agent_count=[1, 1],
              scheduled_agent_count=[0, 0],
              expected_scheduled_agent_count=[0, 0])),

        ('HA router, not scheduled, agent in specified AZ activated',
         dict(az_count=3,
              router_az_hints=2,
              agent_az='az1',
              agent_count=[1, 1, 1],
              max_l3_agents_per_router=2,
              down_agent_count=[0, 1, 0],
              scheduled_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[0, 1, 0])),

        ('HA router, not scheduled, agent not in specified AZ activated',
         dict(az_count=3,
              router_az_hints=2,
              agent_az='az2',
              agent_count=[1, 1, 1],
              max_l3_agents_per_router=2,
              down_agent_count=[0, 0, 1],
              scheduled_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[0, 0, 0])),

    ]

    def test_auto_schedule_router(self):
        scheduler = l3_agent_scheduler.AZLeastRoutersScheduler()
        ha = False
        if self.max_l3_agents_per_router:
            self.config(max_l3_agents_per_router=self.max_l3_agents_per_router)
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
                scheduler.bind_router(self.l3_plugin, self.adminContext,
                                      router['id'], agent.id)

        # activate down agent and call auto_schedule_routers
        activate_agent = l3_agents[self.agent_az][0]
        helpers.set_agent_admin_state(activate_agent['id'],
                                      admin_state_up=True)

        scheduler.auto_schedule_routers(self.l3_plugin, self.adminContext,
                                        activate_agent['host'])

        scheduled_agents = self.l3_plugin.get_l3_agents_hosting_routers(
            self.adminContext, [router['id']])

        scheduled_azs = collections.defaultdict(int)
        for agent in scheduled_agents:
            scheduled_azs[agent['availability_zone']] += 1

        for i in range(self.az_count):
            self.assertEqual(self.expected_scheduled_agent_count[i],
                             scheduled_azs.get('az%s' % i, 0))


class L3DVRSchedulerBaseTest(L3SchedulerBaseTest):

    """Base class for functional test of DVR L3 schedulers.
       Provides basic setup and utility functions.
    """

    def setUp(self):
        super(L3DVRSchedulerBaseTest, self).setUp()

        self.default_ext_net_id = _uuid()
        self.default_ext_subnet_id = _uuid()

        self.router_ext_net_id = _uuid()
        self.router_ext_subnet_id = _uuid()

    def _create_router(self, name, distributed, ext_net_id=None):
        router = {'name': name, 'admin_state_up': True,
                  'tenant_id': self.adminContext.tenant_id,
                  'distributed': distributed}

        if ext_net_id:
            router['external_gateway_info'] = {'network_id': ext_net_id}

        return self.l3_plugin.create_router(self.adminContext,
                                            {'router': router})

    def _create_network(self, net_id, name=None, external=False):
        network_dict = {'tenant_id': self.adminContext.tenant_id,
                        'id': net_id,
                        'name': name,
                        'admin_state_up': True,
                        'shared': False,
                        'status': constants.NET_STATUS_ACTIVE}
        network = self.plugin.create_network(self.adminContext,
                                             {'network': network_dict})
        if external:
            network = net_obj.ExternalNetwork(
                self.adminContext, network_id=net_id)
            network.create()

        return network

    def _create_subnet(self, sub_id, network_id, cidr, gw_ip, name='test_sub'):
        subnet = {'tenant_id': self.adminContext.tenant_id,
                  'id': sub_id,
                  'name': name,
                  'network_id': network_id,
                  'ip_version': 4,
                  'cidr': cidr,
                  'enable_dhcp': False,
                  'gateway_ip': gw_ip,
                  'shared': False,
                  'allocation_pools': constants.ATTR_NOT_SPECIFIED,
                  'dns_nameservers': constants.ATTR_NOT_SPECIFIED,
                  'host_routes': constants.ATTR_NOT_SPECIFIED}

        return self.plugin.create_subnet(self.adminContext, {'subnet': subnet})


class L3DVRSchedulerTestCase(L3DVRSchedulerBaseTest):

    """Test various scenarios for L3 DVR schedulers:

        agent_mode
            L3 agent mode.

        second_agent_mode
            Second L3 agent mode for scenarios with two agents.

        agent_has_ext_network
            Is there external network on the host.

        router_is_distributed
            Is router distributed.

        router_already_hosted
            Is router already hosted.

        router_has_ext_gw
            Does router have external gateway.

        router_agent_have_same_ext_net
            Do router and agent have the same external network.

        expected_router_scheduled
            To verify do we expect router to get scheduled.
    """

    def get_scenario(agent_mode=constants.L3_AGENT_MODE_DVR_SNAT,
                     second_agent_mode=None,
                     agent_has_ext_network=False,
                     router_is_distributed=False,
                     router_already_hosted=False,
                     router_has_ext_gw=False,
                     router_agent_have_same_ext_net=False,
                     expected_router_scheduled=False):
        return dict(agent_mode=agent_mode,
            second_agent_mode=second_agent_mode,
            agent_has_ext_network=agent_has_ext_network,
            router_is_distributed=router_is_distributed,
            router_already_hosted=router_already_hosted,
            router_has_ext_gw=router_has_ext_gw,
            router_agent_have_same_ext_net=router_agent_have_same_ext_net,
            expected_router_scheduled=expected_router_scheduled)

    scenarios = [
        ('Legacy router not scheduled on dvr agent',
         get_scenario(agent_mode=constants.L3_AGENT_MODE_DVR)),

        ('Legacy router scheduled on dvr_snat agent',
         get_scenario(expected_router_scheduled=True)),

        ('Distributed router not scheduled on legacy agent',
         get_scenario(agent_mode=constants.L3_AGENT_MODE_LEGACY,
                      router_is_distributed=True)),

        ('Distributed router not scheduled on dvr agent',
         get_scenario(agent_mode=constants.L3_AGENT_MODE_DVR,
                      router_is_distributed=True)),

        ('Distributed router scheduled on dvr_snat agent',
         get_scenario(router_is_distributed=True,
                      expected_router_scheduled=True)),

        ('Already hosted legacy router not scheduled on dvr agent',
         get_scenario(agent_mode=constants.L3_AGENT_MODE_DVR,
                      router_already_hosted=True)),

        ('Already hosted legacy router not scheduled on dvr_snat agent',
         get_scenario(router_already_hosted=True)),

        ('Already hosted distributed router not scheduled on legacy agent',
         get_scenario(agent_mode=constants.L3_AGENT_MODE_LEGACY,
                      router_already_hosted=True,
                      router_is_distributed=True)),

        ('Already hosted distributed router not scheduled on dvr agent',
         get_scenario(agent_mode=constants.L3_AGENT_MODE_DVR,
                      router_is_distributed=True,
                      router_already_hosted=True)),

        ('Already hosted distributed router not scheduled on dvr_snat agent',
         get_scenario(router_is_distributed=True,
                      router_already_hosted=True)),

        ('Already hosted legacy router not scheduled on additional dvr agent',
         get_scenario(agent_mode=constants.L3_AGENT_MODE_LEGACY,
                      second_agent_mode=constants.L3_AGENT_MODE_DVR_SNAT,
                      router_already_hosted=True)),

        ('Distributed router not scheduled if it is on a different '
         'external network than the dvr_snat agent',
         get_scenario(agent_has_ext_network=True,
                      router_is_distributed=True,
                      router_has_ext_gw=True,
                      router_agent_have_same_ext_net=False)),
    ]

    def setUp(self):
        super(L3DVRSchedulerTestCase, self).setUp()

        agent_cnt = 2 if self.second_agent_mode else 1

        # create hosts for each agent
        self.hosts = ['host-%s' % i for i in range(agent_cnt)]

        # create default external network
        self._create_network(self.default_ext_net_id,
                             name='_test-ext-net', external=True)
        self._create_subnet(self.default_ext_subnet_id,
                            self.default_ext_net_id,
                            '10.10.9.0/24', '10.10.9.1',
                            '_test-ext-net-subnet')

        if self.router_has_ext_gw and not self.router_agent_have_same_ext_net:
            # for the test cases in which router and agent are not on same
            # external network, we create an external network for router
            self._create_network(self.router_ext_net_id,
                                 name='_test-ext-net2', external=True)
            self._create_subnet(self.router_ext_subnet_id,
                                self.router_ext_net_id,
                                '10.10.8.0/24', '10.10.8.1',
                                '_test-ext-net2-subnet')
        # create agents:
        self.l3_agents = [self._create_l3_agent(self.hosts[0],
            self.adminContext, self.agent_mode, True,
            self.default_ext_net_id if self.agent_has_ext_network else '')]
        if self.second_agent_mode:
            self.l3_agents.append(self._create_l3_agent(self.hosts[1],
                self.adminContext, self.second_agent_mode, True,
                self.default_ext_net_id if self.agent_has_ext_network else ''))

        # The router to schedule:
        self.router_to_schedule = self._create_router_to_schedule()

    def _create_router_to_schedule(self):
        router_to_schedule = None

        if self.router_has_ext_gw:
            if self.router_agent_have_same_ext_net:
                router_to_schedule = self._create_router('schd_rtr',
                    self.router_is_distributed,
                    self.default_ext_net_id)
            else:
                router_to_schedule = self._create_router('schd_rtr',
                    self.router_is_distributed,
                    self.router_ext_net_id)
        else:
            router_to_schedule = self._create_router('schd_rtr',
                self.router_is_distributed)

        return router_to_schedule

    def _test_schedule_router(self):
        if self.router_already_hosted:
            self.scheduler.bind_router(self.l3_plugin,
                                       self.adminContext,
                                       self.router_to_schedule['id'],
                                       self.l3_agents[0].id)

        # schedule:
        actual_scheduled_agent = self.scheduler.schedule(
                                     self.l3_plugin,
                                     self.adminContext,
                                     self.router_to_schedule['id'])

        # check for router scheduling:
        self.assertEqual(self.expected_router_scheduled,
                         bool(actual_scheduled_agent),
                         message='Failed to schedule agent')

    def _test_auto_schedule_routers(self):
        if self.router_already_hosted:
            self.scheduler.bind_router(self.l3_plugin,
                                       self.adminContext,
                                       self.router_to_schedule['id'],
                                       self.l3_agents[0].id)
        # schedule:
        hosting_before = self.l3_plugin.get_l3_agents_hosting_routers(
            self.adminContext, [self.router_to_schedule['id']])

        for host in self.hosts:
            self.scheduler.auto_schedule_routers(
                self.l3_plugin, self.adminContext, host)

        hosting_after = self.l3_plugin.get_l3_agents_hosting_routers(
            self.adminContext, [self.router_to_schedule['id']])

        if self.router_already_hosted:
            self.assertEqual(hosting_before, hosting_after,
                             'Agent pre scheduled, yet no binding found!')
        elif self.expected_router_scheduled:
            self.assertNotEqual(hosting_before, hosting_after,
                                'Agent not scheduled, not expected')
        else:
            self.assertEqual(hosting_before, hosting_after,
                             'Agent scheduled, not expected')

    def test_least_routers_schedule_router(self):
        self.scheduler = l3_agent_scheduler.LeastRoutersScheduler()
        self._test_schedule_router()

    def test_least_routers_auto_schedule_routers(self):
        self.scheduler = l3_agent_scheduler.LeastRoutersScheduler()
        self._test_auto_schedule_routers()

    def test_chance_schedule_router(self):
        self.scheduler = l3_agent_scheduler.ChanceScheduler()
        self._test_schedule_router()

    def test_chance_auto_schedule_routers(self):
        self.scheduler = l3_agent_scheduler.ChanceScheduler()
        self._test_auto_schedule_routers()
