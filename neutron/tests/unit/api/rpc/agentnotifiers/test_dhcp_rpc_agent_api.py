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

import contextlib

import mock

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import utils
from neutron import manager
from neutron.tests import base


class TestDhcpAgentNotifyAPI(base.BaseTestCase):

    def setUp(self):
        super(TestDhcpAgentNotifyAPI, self).setUp()
        self.notify = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()

    def test_get_enabled_dhcp_agents_filters_disabled_agents(self):
        disabled_agent = mock.Mock()
        disabled_agent.admin_state_up = False
        enabled_agent = mock.Mock()
        with mock.patch.object(manager.NeutronManager,
                               'get_plugin') as mock_get_plugin:
            mock_get_plugin.return_value = mock_plugin = mock.Mock()
            with mock.patch.object(
                mock_plugin, 'get_dhcp_agents_hosting_networks'
            ) as mock_get_agents:
                mock_get_agents.return_value = [disabled_agent, enabled_agent]
                result = self.notify._get_enabled_dhcp_agents('ctx', 'net_id')
        self.assertEqual(result, [enabled_agent])

    def _test_notification(self, agents):
        with contextlib.nested(
            mock.patch.object(manager.NeutronManager, 'get_plugin'),
            mock.patch.object(utils, 'is_extension_supported'),
            mock.patch.object(self.notify, '_get_enabled_dhcp_agents')
        ) as (m1, m2, mock_get_agents):
            mock_get_agents.return_value = agents
            self.notify._notification(mock.Mock(), 'foo', {}, 'net_id')

    def test_notification_sends_cast_for_enabled_agent(self):
        with mock.patch.object(self.notify, 'cast') as mock_cast:
            self._test_notification([mock.Mock()])
        self.assertEqual(mock_cast.call_count, 1)

    def test_notification_logs_error_for_no_enabled_agents(self):
        with mock.patch.object(self.notify, 'cast') as mock_cast:
            with mock.patch.object(dhcp_rpc_agent_api.LOG,
                                   'error') as mock_log:
                self._test_notification([])
        self.assertEqual(mock_cast.call_count, 0)
        self.assertEqual(mock_log.call_count, 1)

    def test_notification_logs_warning_for_inactive_agents(self):
        agent = mock.Mock()
        agent.is_active = False
        with mock.patch.object(self.notify, 'cast') as mock_cast:
            with mock.patch.object(dhcp_rpc_agent_api.LOG,
                                   'warning') as mock_log:
                self._test_notification([agent])
        self.assertEqual(mock_cast.call_count, 1)
        self.assertEqual(mock_log.call_count, 1)
