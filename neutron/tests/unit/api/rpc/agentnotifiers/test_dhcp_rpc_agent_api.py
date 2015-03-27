# Copyright (c) 2013 Red Hat, Inc.
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

from oslo_utils import timeutils

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import utils
from neutron.db import agents_db
from neutron.db.agentschedulers_db import cfg
from neutron.tests import base


class TestDhcpAgentNotifyAPI(base.BaseTestCase):

    def setUp(self):
        super(TestDhcpAgentNotifyAPI, self).setUp()
        self.notifier = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI(plugin=mock.Mock()))

        mock_util_p = mock.patch.object(utils, 'is_extension_supported')
        mock_log_p = mock.patch.object(dhcp_rpc_agent_api, 'LOG')
        mock_fanout_p = mock.patch.object(self.notifier, '_fanout_message')
        mock_cast_p = mock.patch.object(self.notifier, '_cast_message')
        self.mock_util = mock_util_p.start()
        self.mock_log = mock_log_p.start()
        self.mock_fanout = mock_fanout_p.start()
        self.mock_cast = mock_cast_p.start()

    def _test__schedule_network(self, network,
                                new_agents=None, existing_agents=None,
                                expected_casts=0, expected_warnings=0):
        self.notifier.plugin.schedule_network.return_value = new_agents
        agents = self.notifier._schedule_network(
            mock.ANY, network, existing_agents)
        if new_agents is None:
            new_agents = []
        self.assertEqual(new_agents + existing_agents, agents)
        self.assertEqual(expected_casts, self.mock_cast.call_count)
        self.assertEqual(expected_warnings, self.mock_log.warn.call_count)

    def test__schedule_network(self):
        agent = agents_db.Agent()
        agent.admin_state_up = True
        agent.heartbeat_timestamp = timeutils.utcnow()
        network = {'id': 'foo_net_id'}
        self._test__schedule_network(network,
                                     new_agents=[agent], existing_agents=[],
                                     expected_casts=1, expected_warnings=0)

    def test__schedule_network_no_existing_agents(self):
        agent = agents_db.Agent()
        agent.admin_state_up = True
        agent.heartbeat_timestamp = timeutils.utcnow()
        network = {'id': 'foo_net_id'}
        self._test__schedule_network(network,
                                     new_agents=None, existing_agents=[agent],
                                     expected_casts=0, expected_warnings=0)

    def test__schedule_network_no_new_agents(self):
        network = {'id': 'foo_net_id'}
        self._test__schedule_network(network,
                                     new_agents=None, existing_agents=[],
                                     expected_casts=0, expected_warnings=1)

    def _test__get_enabled_agents(self, network,
                                  agents=None, port_count=0,
                                  expected_warnings=0, expected_errors=0):
        self.notifier.plugin.get_ports_count.return_value = port_count
        enabled_agents = self.notifier._get_enabled_agents(
            mock.ANY, network, agents, mock.ANY, mock.ANY)
        self.assertEqual(agents, enabled_agents)
        self.assertEqual(expected_warnings, self.mock_log.warn.call_count)
        self.assertEqual(expected_errors, self.mock_log.error.call_count)

    def test__get_enabled_agents(self):
        agent1 = agents_db.Agent()
        agent1.admin_state_up = True
        agent1.heartbeat_timestamp = timeutils.utcnow()
        agent2 = agents_db.Agent()
        agent2.admin_state_up = False
        agent2.heartbeat_timestamp = timeutils.utcnow()
        network = {'id': 'foo_network_id'}
        self._test__get_enabled_agents(network, agents=[agent1])

    def test__get_enabled_agents_with_inactive_ones(self):
        agent1 = agents_db.Agent()
        agent1.admin_state_up = True
        agent1.heartbeat_timestamp = timeutils.utcnow()
        agent2 = agents_db.Agent()
        agent2.admin_state_up = True
        # This is effectively an inactive agent
        agent2.heartbeat_timestamp = datetime.datetime(2000, 1, 1, 0, 0)
        network = {'id': 'foo_network_id'}
        self._test__get_enabled_agents(network,
                                       agents=[agent1, agent2],
                                       expected_warnings=1, expected_errors=0)

    def test__get_enabled_agents_with_notification_required(self):
        network = {'id': 'foo_network_id', 'subnets': ['foo_subnet_id']}
        self._test__get_enabled_agents(network, [], port_count=20,
                                       expected_warnings=0, expected_errors=1)

    def test__get_enabled_agents_with_admin_state_down(self):
        cfg.CONF.set_override(
            'enable_services_on_agents_with_admin_state_down', True)
        agent1 = agents_db.Agent()
        agent1.admin_state_up = True
        agent1.heartbeat_timestamp = timeutils.utcnow()
        agent2 = agents_db.Agent()
        agent2.admin_state_up = False
        agent2.heartbeat_timestamp = timeutils.utcnow()
        network = {'id': 'foo_network_id'}
        self._test__get_enabled_agents(network, agents=[agent1, agent2])

    def test__notify_agents_fanout_required(self):
        self.notifier._notify_agents(mock.ANY,
                                     'network_delete_end',
                                     mock.ANY, 'foo_network_id')
        self.assertEqual(1, self.mock_fanout.call_count)

    def _test__notify_agents(self, method,
                             expected_scheduling=0, expected_casts=0):
        with mock.patch.object(self.notifier, '_schedule_network') as f:
            with mock.patch.object(self.notifier, '_get_enabled_agents') as g:
                agent = agents_db.Agent()
                agent.admin_state_up = True
                agent.heartbeat_timestamp = timeutils.utcnow()
                g.return_value = [agent]
                dummy_payload = {'port': {}}
                self.notifier._notify_agents(mock.Mock(), method,
                                             dummy_payload, 'foo_network_id')
                self.assertEqual(expected_scheduling, f.call_count)
                self.assertEqual(expected_casts, self.mock_cast.call_count)

    def test__notify_agents_cast_required_with_scheduling(self):
        self._test__notify_agents('port_create_end',
                                  expected_scheduling=1, expected_casts=1)

    def test__notify_agents_cast_required_wo_scheduling_on_port_update(self):
        self._test__notify_agents('port_update_end',
                                  expected_scheduling=0, expected_casts=1)

    def test__notify_agents_cast_required_with_scheduling_subnet_create(self):
        self._test__notify_agents('subnet_create_end',
                                  expected_scheduling=1, expected_casts=1)

    def test__notify_agents_no_action(self):
        self._test__notify_agents('network_create_end',
                                  expected_scheduling=0, expected_casts=0)

    def test__fanout_message(self):
        self.notifier._fanout_message(mock.ANY, mock.ANY, mock.ANY)
        self.assertEqual(1, self.mock_fanout.call_count)

    def test__cast_message(self):
        self.notifier._cast_message(mock.ANY, mock.ANY, mock.ANY)
        self.assertEqual(1, self.mock_cast.call_count)
