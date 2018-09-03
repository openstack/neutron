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

import collections
from operator import attrgetter

from neutron_lib.api.definitions import provider_net as providernet
from neutron_lib import constants
from neutron_lib import context
from oslo_utils import uuidutils
import testscenarios

from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import common_db_mixin
from neutron.objects import network
from neutron.scheduler import dhcp_agent_scheduler
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron.tests.unit.scheduler import (test_dhcp_agent_scheduler as
                                          test_dhcp_sch)

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
            self.assertItemsEqual(
                (agent['id'] for agent in actual_scheduled_agents),
                (agent['id'] for agent in sorted_unscheduled_active_agents))
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

        no_network_with_az_match
            If this parameter is True, there is no unscheduled network with
            availability_zone_hints matches to an availability_zone of agents
            to be scheduled. The default is False.
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

        ('No agents scheduled if unscheduled network does not match AZ',
         dict(agent_count=1,
              max_agents_per_network=1,
              network_count=1,
              networks_with_dhcp_disabled=[],
              hosted_networks={},
              expected_auto_schedule_return_value=True,
              expected_hosted_networks={'agent-0': []},
              no_network_with_az_match=True)),
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
        for net in self._networks:
            enable_dhcp = (self._strip_host_index(net['name']) not in
                           self.networks_with_dhcp_disabled)
            subnets.append({'network_id': net.id,
                            'enable_dhcp': enable_dhcp,
                            'segment_id': None})
        return subnets

    def get_network(self, context, net_id):
        az_hints = []
        if getattr(self, 'no_network_with_az_match', False):
            az_hints = ['not-match']
        return {'availability_zone_hints': az_hints}

    def _get_hosted_networks_on_dhcp_agent(self, agent_id):
        binding_objs = network.NetworkDhcpAgentBinding.get_objects(
            self.ctx, dhcp_agent_id=agent_id)
        return [item.network_id for item in binding_objs]

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
        self._networks = [
            network.Network(
                self.ctx,
                id=uuidutils.generate_uuid(),
                name='%s-network-%s' % (host_index, i))
            for i in range(self.network_count)
        ]
        for i in range(len(self._networks)):
            self._networks[i].create()
        network_ids = [net.id for net in self._networks]

        # pre schedule the networks to the agents defined in
        # self.hosted_networks before calling auto_schedule_network
        for agent, networks in self.hosted_networks.items():
            agent_index = self._extract_index(agent)
            for net in networks:
                net_index = self._extract_index(net)
                scheduler.resource_filter.bind(self.ctx,
                                               [dhcp_agents[agent_index]],
                                               network_ids[net_index])

        retval = scheduler.auto_schedule_networks(self, self.ctx,
                                                  hosts[host_index])
        self.assertEqual(self.expected_auto_schedule_return_value, retval,
                         message=msg)

        agent_id = dhcp_agents[host_index].id
        hosted_networks = self._get_hosted_networks_on_dhcp_agent(agent_id)
        hosted_net_names = [
            self._strip_host_index(net['name'])
            for net in network.Network.get_objects(
                self.ctx, id=hosted_networks)
        ]
        expected_hosted_networks = self.expected_hosted_networks['agent-%s' %
                                                                 host_index]
        self.assertItemsEqual(hosted_net_names, expected_hosted_networks, msg)

    def test_auto_schedule(self):
        for i in range(self.agent_count):
            self._test_auto_schedule(i)


class TestAZAwareWeightScheduler(test_dhcp_sch.TestDhcpSchedulerBaseTestCase,
                                 agentschedulers_db.DhcpAgentSchedulerDbMixin,
                                 agents_db.AgentDbMixin,
                                 common_db_mixin.CommonDbMixin):
    """Test various scenarios for AZAwareWeightScheduler.schedule.

        az_count
            Number of AZs.

        network_az_hints
            Number of AZs in availability_zone_hints of the network.

        agent_count[each az]
            Number of dhcp agents (also number of hosts).

        max_agents_per_network
            Maximum  DHCP Agents that can be scheduled for a network.

        scheduled_agent_count[each az]
            Number of agents the network has previously scheduled

        down_agent_count[each az]
            Number of dhcp agents which are down

        expected_scheduled_agent_count[each az]
            Number of scheduled agents the schedule() should return
            or 'None' if the schedule() cannot schedule the network.
    """

    scenarios = [
        ('Single hint, Single agent, Scheduled an agent of the specified AZ',
         dict(az_count=2,
              network_az_hints=1,
              agent_count=[1, 1],
              max_agents_per_network=1,
              scheduled_agent_count=[0, 0],
              down_agent_count=[0, 0],
              expected_scheduled_agent_count=[1, 0])),

        ('Multi hints, Multi agents Scheduled agents of the specified AZs',
         dict(az_count=3,
              network_az_hints=2,
              agent_count=[1, 1, 1],
              max_agents_per_network=2,
              scheduled_agent_count=[0, 0, 0],
              down_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[1, 1, 0])),

        ('Single hint, Multi agents, Scheduled agents of the specified AZ',
         dict(az_count=2,
              network_az_hints=1,
              agent_count=[2, 1],
              max_agents_per_network=2,
              scheduled_agent_count=[0, 0],
              down_agent_count=[0, 0],
              expected_scheduled_agent_count=[2, 0])),

        ('Multi hints, Multi agents, Only single AZ available',
         dict(az_count=2,
              network_az_hints=2,
              agent_count=[2, 1],
              max_agents_per_network=2,
              scheduled_agent_count=[0, 0],
              down_agent_count=[0, 1],
              expected_scheduled_agent_count=[2, 0])),

        ('Multi hints, Multi agents, Not enough agents',
         dict(az_count=3,
              network_az_hints=3,
              agent_count=[1, 1, 1],
              max_agents_per_network=3,
              scheduled_agent_count=[0, 0, 0],
              down_agent_count=[0, 1, 0],
              expected_scheduled_agent_count=[1, 0, 1])),

        ('Multi hints, Multi agents, Partially scheduled, Another AZ selected',
         dict(az_count=3,
              network_az_hints=2,
              agent_count=[1, 1, 1],
              max_agents_per_network=2,
              scheduled_agent_count=[1, 0, 0],
              down_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[0, 1, 0])),

        ('No hint, Scheduled independent to AZ',
         dict(az_count=3,
              network_az_hints=0,
              agent_count=[1, 1, 1],
              max_agents_per_network=3,
              scheduled_agent_count=[0, 0, 0],
              down_agent_count=[0, 0, 0],
              expected_scheduled_agent_count=[1, 1, 1])),
    ]

    def _set_network_az_hints(self):
        self.network['availability_zone_hints'] = []
        for i in range(self.network_az_hints):
            self.network['availability_zone_hints'].append('az%s' % i)

    def test_schedule_network(self):
        self.config(dhcp_agents_per_network=self.max_agents_per_network)
        scheduler = dhcp_agent_scheduler.AZAwareWeightScheduler()
        self._set_network_az_hints()

        # create dhcp agents
        for i in range(self.az_count):
            az = 'az%s' % i
            hosts = ['%s-host-%s' % (az, j)
                     for j in range(self.agent_count[i])]
            dhcp_agents = self._create_and_set_agents_down(
                hosts, down_agent_count=self.down_agent_count[i], az=az)

            active_agents = dhcp_agents[self.down_agent_count[i]:]

            # schedule some agents before calling schedule
            if self.scheduled_agent_count[i]:
                # schedule the network
                schedule_agents = active_agents[:self.scheduled_agent_count[i]]
                scheduler.resource_filter.bind(
                    self.ctx, schedule_agents, self.network_id)

        actual_scheduled_agents = scheduler.schedule(self, self.ctx,
                                                     self.network)
        scheduled_azs = collections.defaultdict(int)
        for agent in actual_scheduled_agents:
            scheduled_azs[agent['availability_zone']] += 1

        hosted_agents = self.list_dhcp_agents_hosting_network(
                            self.ctx, self.network_id)
        hosted_azs = collections.defaultdict(int)
        for agent in hosted_agents['agents']:
            hosted_azs[agent['availability_zone']] += 1

        for i in range(self.az_count):
            self.assertEqual(self.expected_scheduled_agent_count[i],
                             scheduled_azs.get('az%s' % i, 0))
            self.assertEqual(self.scheduled_agent_count[i] +
                             scheduled_azs.get('az%s' % i, 0),
                             hosted_azs.get('az%s' % i, 0))


class TestDHCPSchedulerWithNetworkAccessibility(
    test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['openvswitch']

    def test_dhcp_scheduler_filters_hosts_without_network_access(self):
        dhcp_agent1 = helpers.register_dhcp_agent(host='host1')
        dhcp_agent2 = helpers.register_dhcp_agent(host='host2')
        dhcp_agent3 = helpers.register_dhcp_agent(host='host3')
        dhcp_agents = [dhcp_agent1, dhcp_agent2, dhcp_agent3]
        helpers.register_ovs_agent(
            host='host1', bridge_mappings={'physnet1': 'br-eth-1'})
        helpers.register_ovs_agent(
            host='host2', bridge_mappings={'physnet2': 'br-eth-1'})
        helpers.register_ovs_agent(
            host='host3', bridge_mappings={'physnet2': 'br-eth-1'})
        admin_context = context.get_admin_context()
        net = self.driver.create_network(
            admin_context,
            {'network': {'name': 'net1',
                         providernet.NETWORK_TYPE: 'vlan',
                         providernet.PHYSICAL_NETWORK: 'physnet1',
                         providernet.SEGMENTATION_ID: 1,
                         'tenant_id': 'tenant_one',
                         'admin_state_up': True,
                         'shared': True}})

        self.driver.create_subnet(
            admin_context,
            {'subnet':
                {'name': 'name',
                 'ip_version': constants.IP_VERSION_4,
                 'network_id': net['id'],
                 'cidr': '10.0.0.0/24',
                 'gateway_ip': constants.ATTR_NOT_SPECIFIED,
                 'allocation_pools': constants.ATTR_NOT_SPECIFIED,
                 'dns_nameservers': constants.ATTR_NOT_SPECIFIED,
                 'host_routes': constants.ATTR_NOT_SPECIFIED,
                 'tenant_id': 'tenant_one',
                 'enable_dhcp': True}})

        self.plugin.schedule_network(admin_context, net)
        dhcp_agents = self.driver.get_dhcp_agents_hosting_networks(
            admin_context, [net['id']])
        self.assertEqual(1, len(dhcp_agents))
        self.assertEqual('host1', dhcp_agents[0]['host'])
