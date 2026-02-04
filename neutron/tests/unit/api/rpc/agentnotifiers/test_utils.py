# Copyright (c) 2026 Red Hat Inc.
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

from unittest import mock

from neutron.api.rpc.agentnotifiers import utils as notifier_utils
from neutron.tests import base as test_base


class _RPCNotifier:
    def method_1(self, *args, **kwargs):
        return 'method_1_return'


class TestRPCNotifierHandler(test_base.BaseTestCase):
    def test_call_existing_method(self):
        handler = notifier_utils.RPCNotifierHandler()
        handler.notifier_instance = _RPCNotifier()
        self.assertEqual('method_1_return',
                         handler.method_1(1, arg2=2))

    @mock.patch.object(notifier_utils, 'LOG')
    def test_call_non_existing_method(self, mock_log):
        handler = notifier_utils.RPCNotifierHandler()
        handler.notifier_instance = _RPCNotifier()
        self.assertIsNone(handler.method_2(1, arg2=2))
        mock_log.warning.assert_called_once_with(
            'Method method_2 is not implemented in the RPC notifier.')

    def test_call_no_rpc_instance(self):
        handler = notifier_utils.RPCNotifierHandler()
        self.assertIsNone(handler.method_any(1, arg2=2))
