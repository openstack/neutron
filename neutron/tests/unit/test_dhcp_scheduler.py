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

import mock

from neutron.common import constants
from neutron.common import topics
from neutron import context
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import models_v2
from neutron.openstack.common import timeutils
from neutron.scheduler import dhcp_agent_scheduler
from neutron.tests.unit import testlib_api


class DhcpSchedulerTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(DhcpSchedulerTestCase, self).setUp()
        self.ctx = context.get_admin_context()
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

    def _save_networks(self, networks):
        for network_id in networks:
            with self.ctx.session.begin(subtransactions=True):
                self.ctx.session.add(models_v2.Network(id=network_id))

    def _test_schedule_bind_network(self, agents, network_id):
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        scheduler._schedule_bind_network(self.ctx, agents, network_id)
        results = (
            self.ctx.session.query(agentschedulers_db.NetworkDhcpAgentBinding).
            filter_by(network_id=network_id).all())
        self.assertEqual(len(agents), len(results))
        for result in results:
            self.assertEqual(network_id, result.network_id)

    def test_schedule_bind_network_single_agent(self):
        agents = self._get_agents(['host-a'])
        self._save_agents(agents)
        self._test_schedule_bind_network(agents, self.network_id)

    def test_schedule_bind_network_multi_agents(self):
        agents = self._get_agents(['host-a', 'host-b'])
        self._save_agents(agents)
        self._test_schedule_bind_network(agents, self.network_id)

    def test_schedule_bind_network_multi_agent_fail_one(self):
        agents = self._get_agents(['host-a'])
        self._save_agents(agents)
        self._test_schedule_bind_network(agents, self.network_id)
        with mock.patch.object(dhcp_agent_scheduler.LOG, 'info') as fake_log:
            self._test_schedule_bind_network(agents, self.network_id)
            self.assertEqual(1, fake_log.call_count)

    def test_auto_schedule_networks_no_networks(self):
        plugin = mock.MagicMock()
        plugin.get_networks.return_value = []
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        self.assertFalse(scheduler.auto_schedule_networks(plugin,
                                                          self.ctx, "host-a"))

    def test_auto_schedule_networks(self):
        plugin = mock.MagicMock()
        plugin.get_subnets.return_value = [{"network_id": self.network_id,
                                            "enable_dhcp": True}]
        agents = self._get_agents(['host-a'])
        self._save_agents(agents)
        scheduler = dhcp_agent_scheduler.ChanceScheduler()

        self.assertTrue(scheduler.auto_schedule_networks(plugin,
                                                         self.ctx, "host-a"))
        results = (
            self.ctx.session.query(agentschedulers_db.NetworkDhcpAgentBinding)
            .all())
        self.assertEqual(1, len(results))

    def test_auto_schedule_networks_network_already_scheduled(self):
        plugin = mock.MagicMock()
        plugin.get_subnets.return_value = [{"network_id": self.network_id,
                                            "enable_dhcp": True}]
        agents = self._get_agents(['host-a'])
        self._save_agents(agents)
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        self._test_schedule_bind_network(agents, self.network_id)
        self.assertTrue(scheduler.auto_schedule_networks(plugin,
                                                         self.ctx, "host-a"))
        results = (
            self.ctx.session.query(agentschedulers_db.NetworkDhcpAgentBinding)
            .all())
        self.assertEqual(1, len(results))
