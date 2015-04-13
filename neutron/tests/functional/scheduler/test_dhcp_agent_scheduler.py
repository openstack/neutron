# Copyright (c) 2015 Red Hat, Inc.
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

import six
import testscenarios

from neutron import context
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import common_db_mixin
from neutron.scheduler import dhcp_agent_scheduler
from neutron.tests.unit.scheduler import (test_dhcp_agent_scheduler as
                                          test_dhcp_sch)
from operator import attrgetter

# Required to generate tests from scenarios. Not compatible with nose.
load_tests = testscenarios.load_tests_apply_scenarios


class BaseTestScheduleNetwork(object):
    """Base class which defines scenarios for schedulers.

        agent_count
            Number of dhcp agents (also number of hosts).

        max_agents_per_network
            Maximum  DHCP Agents that can be scheduled for a network.

        scheduled_agent_count
            Number of agents the network has previously scheduled

        down_agent_count
            Number of dhcp agents which are down

        expected_scheduled_agent_count
            Number of scheduled agents the schedule() should return
            or 'None' if the schedule() cannot schedule the network.
    """

    scenarios = [
        ('No agents scheduled if no agents are present',
         dict(agent_count=0,
              max_agents_per_network=1,
              scheduled_agent_count=0,
              down_agent_count=0,
              expected_scheduled_agent_count=None)),

        ('No agents scheduled if network already hosted and'
         ' max_agents_per_network reached',
         dict(agent_count=1,
              max_agents_per_network=1,
              scheduled_agent_count=1,
              down_agent_count=0,
              expected_scheduled_agent_count=None)),

        ('No agents scheduled if all agents are down',
         dict(agent_count=2,
              max_agents_per_network=1,
              scheduled_agent_count=0,
              down_agent_count=2,
              expected_scheduled_agent_count=None)),

        ('Agent scheduled to the network if network is not yet hosted',
         dict(agent_count=1,
              max_agents_per_network=1,
              scheduled_agent_count=0,
              down_agent_count=0,
              expected_scheduled_agent_count=1)),

        ('Additional Agents scheduled to the network if max_agents_per_network'
         ' is not yet reached',
         dict(agent_count=3,
              max_agents_per_network=3,
              scheduled_agent_count=1,
              down_agent_count=0,
              expected_scheduled_agent_count=2)),

        ('No agent scheduled if agent is dead',
         dict(agent_count=3,
              max_agents_per_network=3,
              scheduled_agent_count=1,
              down_agent_count=1,
              expected_scheduled_agent_count=1)),
    ]


class TestChanceScheduleNetwork(test_dhcp_sch.TestDhcpSchedulerBaseTestCase,
                                agentschedulers_db.DhcpAgentSchedulerDbMixin,
                                agents_db.AgentDbMixin,
                                common_db_mixin.CommonDbMixin,
                                BaseTestScheduleNetwork):
    """Test various scenarios for ChanceScheduler.schedule."""

    def test_schedule_network(self):
        self.config(dhcp_agents_per_network=self.max_agents_per_network)
        scheduler = dhcp_agent_scheduler.ChanceScheduler()

        # create dhcp agents
        hosts = ['host-%s' % i for i in range(self.agent_count)]
        dhcp_agents = self._create_and_set_agents_down(
            hosts, down_agent_count=self.down_agent_count)

        active_agents = dhcp_agents[self.down_agent_count:]

        # schedule some agents before calling schedule
        if self.scheduled_agent_count:
            # schedule the network
            schedule_agents = active_agents[:self.scheduled_agent_count]
            scheduler.resource_filter.bind(self.ctx,
                                           schedule_agents, self.network_id)
        actual_scheduled_agents = scheduler.schedule(self, self.ctx,
                                                     self.network)
        if self.expected_scheduled_agent_count:
            self.assertEqual(self.expected_scheduled_agent_count,
                             len(actual_scheduled_agents))
            hosted_agents = self.list_dhcp_agents_hosting_network(
                self.ctx, self.network_id)
            self.assertEqual(self.scheduled_agent_count +
                             len(actual_scheduled_agents),
                             len(hosted_agents['agents']))
        else:
            self.assertEqual([], actual_scheduled_agents)


class TestWeightScheduleNetwork(test_dhcp_sch.TestDhcpSchedulerBaseTestCase,
                                agentschedulers_db.DhcpAgentSchedulerDbMixin,
                                agents_db.AgentDbMixin,
                                common_db_mixin.CommonDbMixin,
                                BaseTestScheduleNetwork):
    """Test various scenarios for WeightScheduler.schedule."""

    def test_weight_schedule_network(self):
        self.config(dhcp_agents_per_network=self.max_agents_per_network)
        scheduler = dhcp_agent_scheduler.WeightScheduler()

        # create dhcp agents
        hosts = ['host-%s' % i for i in range(self.agent_count)]
        dhcp_agents = self._create_and_set_agents_down(
            hosts, down_agent_count=self.down_agent_count)

        active_agents = dhcp_agents[self.down_agent_count:]

        unscheduled_active_agents = list(active_agents)
        # schedule some agents before calling schedule
        if self.scheduled_agent_count:
            # schedule the network
            schedule_agents = active_agents[:self.scheduled_agent_count]
            scheduler.resource_filter.bind(self.ctx,
                                           schedule_agents, self.network_id)
            for agent in schedule_agents:
                unscheduled_active_agents.remove(agent)
        actual_scheduled_agents = scheduler.schedule(self, self.ctx,
                                                     self.network)
        if self.expected_scheduled_agent_count:
            sorted_unscheduled_active_agents = sorted(
                unscheduled_active_agents,
                key=attrgetter('load'))[0:self.expected_scheduled_agent_count]
            self.assertItemsEqual(actual_scheduled_agents,
                                  sorted_unscheduled_active_agents)
            self.assertEqual(self.expected_scheduled_agent_count,
                             len(actual_scheduled_agents))
            hosted_agents = self.list_dhcp_agents_hosting_network(
                self.ctx, self.network_id)
            self.assertEqual(self.scheduled_agent_count +
                             len(actual_scheduled_agents),
                             len(hosted_agents['agents']))
        else:
            self.assertEqual([], actual_scheduled_agents)


class TestAutoSchedule(test_dhcp_sch.TestDhcpSchedulerBaseTestCase,
                       agentschedulers_db.DhcpAgentSchedulerDbMixin,
                       agents_db.AgentDbMixin,
                       common_db_mixin.CommonDbMixin):
    """Test various scenarios for ChanceScheduler.auto_schedule_networks.

        Below is the brief description of the scenario variables
        --------------------------------------------------------
        agent_count
            number of DHCP agents (also number of hosts).

        max_agents_per_network
            Maximum  DHCP Agents that can be scheduled for a network.

        network_count
            Number of networks.

        networks_with_dhcp_disabled
            List of networks with dhcp disabled

        hosted_networks
            A mapping of agent id to the ids of the networks that they
            should be initially hosting.

        expected_auto_schedule_return_value
            Expected return value of 'auto_schedule_networks'.

        expected_hosted_networks
            This stores the expected networks that should have been scheduled
            (or that could have already been scheduled) for each agent
            after the 'auto_schedule_networks' function is called.
    """

    scenarios = [
        ('Agent scheduled to the network if network is not yet hosted',
         dict(agent_count=1,
              max_agents_per_network=1,
              network_count=1,
              networks_with_dhcp_disabled=[],
              hosted_networks={},
              expected_auto_schedule_return_value=True,
              expected_hosted_networks={'agent-0': ['network-0']})),

        ('No agent scheduled if no networks are present',
         dict(agent_count=1,
              max_agents_per_network=1,
              network_count=0,
              networks_with_dhcp_disabled=[],
              hosted_networks={},
              expected_auto_schedule_return_value=False,
              expected_hosted_networks={'agent-0': []})),

        ('Agents scheduled to the networks if networks are not yet hosted',
         dict(agent_count=2,
              max_agents_per_network=3,
              network_count=2,
              networks_with_dhcp_disabled=[],
              hosted_networks={},
              expected_auto_schedule_return_value=True,
              expected_hosted_networks={'agent-0': ['network-0',
                                                    'network-1'],
                                        'agent-1': ['network-0',
                                                    'network-1']})),

        ('No new agents scheduled if networks are already hosted',
         dict(agent_count=2,
              max_agents_per_network=3,
              network_count=2,
              networks_with_dhcp_disabled=[],
              hosted_networks={'agent-0': ['network-0', 'network-1'],
                               'agent-1': ['network-0', 'network-1']},
              expected_auto_schedule_return_value=True,
              expected_hosted_networks={'agent-0': ['network-0',
                                                    'network-1'],
                                        'agent-1': ['network-0',
                                                    'network-1']})),

        ('Additional agents scheduled to the networks if'
         ' max_agents_per_network is not yet reached',
         dict(agent_count=4,
              max_agents_per_network=3,
              network_count=4,
              networks_with_dhcp_disabled=[],
              hosted_networks={'agent-0': ['network-0', 'network-1'],
                               'agent-1': ['network-0'],
                               'agent-2': ['network-2'],
                               'agent-3': ['network-0', 'network-2']},
              expected_auto_schedule_return_value=True,
              expected_hosted_networks={'agent-0': ['network-0',
                                                    'network-1',
                                                    'network-2',
                                                    'network-3'],
                                        'agent-1': ['network-0',
                                                    'network-1',
                                                    'network-2',
                                                    'network-3'],
                                        'agent-2': ['network-1',
                                                    'network-2',
                                                    'network-3'],
                                        'agent-3': ['network-0',
                                                    'network-1',
                                                    'network-2',
                                                    'network-3']})),

        ('No agents scheduled if networks already hosted and'
         ' max_agents_per_network reached',
         dict(agent_count=4,
              max_agents_per_network=1,
              network_count=4,
              networks_with_dhcp_disabled=[],
              hosted_networks={'agent-0': ['network-0'],
                               'agent-1': ['network-2'],
                               'agent-2': ['network-1'],
                               'agent-3': ['network-3']},
              expected_auto_schedule_return_value=True,
              expected_hosted_networks={'agent-0': ['network-0'],
                                        'agent-1': ['network-2'],
                                        'agent-2': ['network-1'],
                                        'agent-3': ['network-3']})),

        ('No agents scheduled to the network with dhcp disabled',
         dict(agent_count=2,
              max_agents_per_network=3,
              network_count=2,
              networks_with_dhcp_disabled=['network-1'],
              hosted_networks={},
              expected_auto_schedule_return_value=True,
              expected_hosted_networks={'agent-0': ['network-0'],
                                        'agent-1': ['network-0']})),

        ('No agents scheduled if all networks have dhcp disabled',
         dict(agent_count=2,
              max_agents_per_network=3,
              network_count=2,
              networks_with_dhcp_disabled=['network-0', 'network-1'],
              hosted_networks={},
              expected_auto_schedule_return_value=False,
              expected_hosted_networks={'agent-0': [],
                                        'agent-1': []})),
    ]

    def _strip_host_index(self, name):
        """Strips the host index.

        Eg. if name = '2-agent-3', then 'agent-3' is returned.
        """
        return name[name.find('-') + 1:]

    def _extract_index(self, name):
        """Extracts the index number and returns.

        Eg. if name = '2-agent-3', then 3 is returned
        """
        return int(name.split('-')[-1])

    def get_subnets(self, context, fields=None):
        subnets = []
        for net_id in self._networks:
            enable_dhcp = (not self._strip_host_index(net_id) in
                           self.networks_with_dhcp_disabled)
            subnets.append({'network_id': net_id,
                            'enable_dhcp': enable_dhcp})
        return subnets

    def _get_hosted_networks_on_dhcp_agent(self, agent_id):
        query = self.ctx.session.query(
            agentschedulers_db.NetworkDhcpAgentBinding.network_id)
        query = query.filter(
            agentschedulers_db.NetworkDhcpAgentBinding.dhcp_agent_id ==
            agent_id)

        return [item[0] for item in query]

    def _test_auto_schedule(self, host_index):
        self.config(dhcp_agents_per_network=self.max_agents_per_network)
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        self.ctx = context.get_admin_context()
        msg = 'host_index = %s' % host_index

        # create dhcp agents
        hosts = ['%s-agent-%s' % (host_index, i)
                 for i in range(self.agent_count)]
        dhcp_agents = self._create_and_set_agents_down(hosts)

        # create networks
        self._networks = ['%s-network-%s' % (host_index, i)
                          for i in range(self.network_count)]
        self._save_networks(self._networks)

        # pre schedule the networks to the agents defined in
        # self.hosted_networks before calling auto_schedule_network
        for agent, networks in six.iteritems(self.hosted_networks):
            agent_index = self._extract_index(agent)
            for net in networks:
                net_index = self._extract_index(net)
                scheduler.resource_filter.bind(self.ctx,
                                               [dhcp_agents[agent_index]],
                                               self._networks[net_index])

        retval = scheduler.auto_schedule_networks(self, self.ctx,
                                                  hosts[host_index])
        self.assertEqual(self.expected_auto_schedule_return_value, retval,
                         message=msg)

        agent_id = dhcp_agents[host_index].id
        hosted_networks = self._get_hosted_networks_on_dhcp_agent(agent_id)
        hosted_net_ids = [self._strip_host_index(net)
                          for net in hosted_networks]
        expected_hosted_networks = self.expected_hosted_networks['agent-%s' %
                                                                 host_index]
        for hosted_net_id in hosted_net_ids:
            self.assertIn(hosted_net_id, expected_hosted_networks,
                          message=msg + '[%s]' % hosted_net_id)

    def test_auto_schedule(self):
        for i in range(self.agent_count):
            self._test_auto_schedule(i)
