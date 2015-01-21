# Copyright 2014 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime

import mock
from oslo.utils import timeutils
import testscenarios


from neutron.common import constants
from neutron.common import topics
from neutron import context
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import models_v2
from neutron.scheduler import dhcp_agent_scheduler
from neutron.tests.unit import testlib_api

# Required to generate tests from scenarios. Not compatible with nose.
load_tests = testscenarios.load_tests_apply_scenarios


class TestDhcpSchedulerBaseTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestDhcpSchedulerBaseTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.network = {'id': 'foo_network_id'}
        self.network_id = 'foo_network_id'
        self._save_networks([self.network_id])

    def _get_agents(self, hosts):
        return [
            agents_db.Agent(
                binary='neutron-dhcp-agent',
                host=host,
                topic=topics.DHCP_AGENT,
                configurations="",
                agent_type=constants.AGENT_TYPE_DHCP,
                created_at=timeutils.utcnow(),
                started_at=timeutils.utcnow(),
                heartbeat_timestamp=timeutils.utcnow())
            for host in hosts
        ]

    def _save_agents(self, agents):
        for agent in agents:
            with self.ctx.session.begin(subtransactions=True):
                self.ctx.session.add(agent)

    def _create_and_set_agents_down(self, hosts, down_agent_count=0):
        dhcp_agents = self._get_agents(hosts)
        # bring down the specified agents
        for agent in dhcp_agents[:down_agent_count]:
            old_time = agent['heartbeat_timestamp']
            hour_old = old_time - datetime.timedelta(hours=1)
            agent['heartbeat_timestamp'] = hour_old
        self._save_agents(dhcp_agents)
        return dhcp_agents

    def _save_networks(self, networks):
        for network_id in networks:
            with self.ctx.session.begin(subtransactions=True):
                self.ctx.session.add(models_v2.Network(id=network_id))

    def _test_schedule_bind_network(self, agents, network_id):
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        scheduler._schedule_bind_network(self.ctx, agents, network_id)
        results = self.ctx.session.query(
            agentschedulers_db.NetworkDhcpAgentBinding).filter_by(
            network_id=network_id).all()
        self.assertEqual(len(agents), len(results))
        for result in results:
            self.assertEqual(network_id, result.network_id)


class TestDhcpScheduler(TestDhcpSchedulerBaseTestCase):

    def test_schedule_bind_network_single_agent(self):
        agents = self._create_and_set_agents_down(['host-a'])
        self._test_schedule_bind_network(agents, self.network_id)

    def test_schedule_bind_network_multi_agents(self):
        agents = self._create_and_set_agents_down(['host-a', 'host-b'])
        self._test_schedule_bind_network(agents, self.network_id)

    def test_schedule_bind_network_multi_agent_fail_one(self):
        agents = self._create_and_set_agents_down(['host-a'])
        self._test_schedule_bind_network(agents, self.network_id)
        with mock.patch.object(dhcp_agent_scheduler.LOG, 'info') as fake_log:
            self._test_schedule_bind_network(agents, self.network_id)
            self.assertEqual(1, fake_log.call_count)


class TestAutoScheduleNetworks(TestDhcpSchedulerBaseTestCase):
    """Unit test scenarios for ChanceScheduler.auto_schedule_networks.

    network_present
        Network is present or not

    enable_dhcp
        Dhcp is enabled or disabled in the subnet of the network

    scheduled_already
        Network is already scheduled to the agent or not

    agent_down
        Dhcp agent is down or alive

    valid_host
        If true, then an valid host is passed to schedule the network,
        else an invalid host is passed.
    """
    scenarios = [
        ('Network present',
         dict(network_present=True,
              enable_dhcp=True,
              scheduled_already=False,
              agent_down=False,
              valid_host=True)),

        ('No network',
         dict(network_present=False,
              enable_dhcp=False,
              scheduled_already=False,
              agent_down=False,
              valid_host=True)),

        ('Network already scheduled',
         dict(network_present=True,
              enable_dhcp=True,
              scheduled_already=True,
              agent_down=False,
              valid_host=True)),

        ('Agent down',
         dict(network_present=True,
              enable_dhcp=True,
              scheduled_already=False,
              agent_down=False,
              valid_host=True)),

        ('dhcp disabled',
         dict(network_present=True,
              enable_dhcp=False,
              scheduled_already=False,
              agent_down=False,
              valid_host=False)),

        ('Invalid host',
         dict(network_present=True,
              enable_dhcp=True,
              scheduled_already=False,
              agent_down=False,
              valid_host=False)),
    ]

    def test_auto_schedule_network(self):
        plugin = mock.MagicMock()
        plugin.get_subnets.return_value = (
            [{"network_id": self.network_id, "enable_dhcp": self.enable_dhcp}]
            if self.network_present else [])
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        if self.network_present:
            down_agent_count = 1 if self.agent_down else 0
            agents = self._create_and_set_agents_down(
                ['host-a'], down_agent_count=down_agent_count)
            if self.scheduled_already:
                self._test_schedule_bind_network(agents, self.network_id)

        expected_result = (self.network_present and self.enable_dhcp)
        expected_hosted_agents = (1 if expected_result and
                                  self.valid_host else 0)
        host = "host-a" if self.valid_host else "host-b"
        observed_ret_value = scheduler.auto_schedule_networks(
            plugin, self.ctx, host)
        self.assertEqual(expected_result, observed_ret_value)
        hosted_agents = self.ctx.session.query(
            agentschedulers_db.NetworkDhcpAgentBinding).all()
        self.assertEqual(expected_hosted_agents, len(hosted_agents))
