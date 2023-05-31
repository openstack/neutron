# Copyright 2022 Red Hat, Inc.
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

import datetime
from unittest import mock

import eventlet

from neutron.common.ovn import constants as ovn_const
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes


class AgentCacheTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.agent_cache = neutron_agent.AgentCache(driver=mock.ANY)
        self.addCleanup(self._clean_agent_cache)
        self.names_ref = []
        for i in range(10):  # Add 10 agents.
            chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
                attrs={'name': 'chassis' + str(i), 'other_config': {}})
            self.agent_cache.update(ovn_const.OVN_CONTROLLER_AGENT,
                                    chassis_private)
            self.names_ref.append('chassis' + str(i))

    def _clean_agent_cache(self):
        self.agent_cache.agents = {}

    def _list_agents(self):
        self.names_read = []
        for idx, agent in enumerate(self.agent_cache):
            self.names_read.append(agent.agent_id)
            if idx == 5:  # Swap to "_add_and_delete_agents" thread.
                eventlet.sleep(0)

    def _add_and_delete_agents(self):
        del self.agent_cache['chassis8']
        chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'chassis10'})
        self.agent_cache.update(ovn_const.OVN_CONTROLLER_AGENT,
                                chassis_private)

    def test_update_while_iterating_agents(self):
        pool = eventlet.GreenPool(2)
        pool.spawn(self._list_agents)
        pool.spawn(self._add_and_delete_agents)
        pool.waitall()
        self.assertEqual(self.names_ref, self.names_read)

    def test_agents_by_chassis_private(self):
        chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'chassis5'})
        agents = self.agent_cache.agents_by_chassis_private(chassis_private)
        agents = list(agents)
        self.assertEqual(1, len(agents))
        self.assertEqual('chassis5', agents[0].agent_id)

    @mock.patch.object(neutron_agent.ControllerAgent, 'alive')
    def test_heartbeat_timestamp_format(self, agent_alive):
        chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'chassis5'})
        agents = self.agent_cache.agents_by_chassis_private(chassis_private)
        agent = list(agents)[0]
        agent.chassis.hostname = 'fake-hostname'
        agent.updated_at = datetime.datetime(
            year=2023, month=2, day=23, hour=1, minute=2, second=3,
            microsecond=456789).replace(tzinfo=datetime.timezone.utc)
        agent_alive.return_value = True

        # Verify that both microseconds and timezone are dropped
        self.assertEqual(str(agent.as_dict()['heartbeat_timestamp']),
                         '2023-02-23 01:02:03')
