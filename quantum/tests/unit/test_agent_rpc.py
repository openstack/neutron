# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation.
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

import mock

from quantum.agent import rpc
from quantum.openstack.common import context
from quantum.tests import base


class AgentRPCPluginApi(base.BaseTestCase):
    def _test_rpc_call(self, method):
        agent = rpc.PluginApi('fake_topic')
        ctxt = context.RequestContext('fake_user', 'fake_project')
        expect_val = 'foo'
        with mock.patch('quantum.openstack.common.rpc.call') as rpc_call:
            rpc_call.return_value = expect_val
            func_obj = getattr(agent, method)
            if method == 'tunnel_sync':
                actual_val = func_obj(ctxt, 'fake_tunnel_ip')
            else:
                actual_val = func_obj(ctxt, 'fake_device', 'fake_agent_id')
        self.assertEqual(actual_val, expect_val)

    def test_get_device_details(self):
        self._test_rpc_call('get_device_details')

    def test_update_device_down(self):
        self._test_rpc_call('update_device_down')

    def test_tunnel_sync(self):
        self._test_rpc_call('tunnel_sync')


class AgentPluginReportState(base.BaseTestCase):
    def test_plugin_report_state(self):
        topic = 'test'
        reportStateAPI = rpc.PluginReportStateAPI(topic)
        expected_agent_state = {'agent': 'test'}
        with mock.patch.object(reportStateAPI, 'call') as call:
            ctxt = context.RequestContext('fake_user', 'fake_project')
            reportStateAPI.report_state(ctxt, expected_agent_state)
            self.assertEqual(call.call_args[0][0], ctxt)
            self.assertEqual(call.call_args[0][1]['method'],
                             'report_state')
            self.assertEqual(call.call_args[0][1]['args']['agent_state'],
                             {'agent_state': expected_agent_state})
            self.assertIsInstance(call.call_args[0][1]['args']['time'],
                                  str)
            self.assertEqual(call.call_args[1]['topic'], topic)


class AgentRPCMethods(base.BaseTestCase):
    def test_create_consumers(self):
        dispatcher = mock.Mock()
        expected = [
            mock.call(new=True),
            mock.call().create_consumer('foo-topic-op', dispatcher,
                                        fanout=True),
            mock.call().consume_in_thread()
        ]

        call_to_patch = 'quantum.openstack.common.rpc.create_connection'
        with mock.patch(call_to_patch) as create_connection:
            rpc.create_consumers(dispatcher, 'foo', [('topic', 'op')])
            create_connection.assert_has_calls(expected)
