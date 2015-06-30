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

from neutron.api.rpc.handlers import securitygroups_rpc
from neutron.tests import base


class SecurityGroupServerRpcApiTestCase(base.BaseTestCase):

    def test_security_group_rules_for_devices(self):
        rpcapi = securitygroups_rpc.SecurityGroupServerRpcApi('fake_topic')

        with mock.patch.object(rpcapi.client, 'call') as rpc_mock,\
                mock.patch.object(rpcapi.client, 'prepare') as prepare_mock:
            prepare_mock.return_value = rpcapi.client
            rpcapi.security_group_rules_for_devices('context', ['fake_device'])

            rpc_mock.assert_called_once_with(
                    'context',
                    'security_group_rules_for_devices',
                    devices=['fake_device'])


class SGAgentRpcCallBackMixinTestCase(base.BaseTestCase):

    def setUp(self):
        super(SGAgentRpcCallBackMixinTestCase, self).setUp()
        self.rpc = securitygroups_rpc.SecurityGroupAgentRpcCallbackMixin()
        self.rpc.sg_agent = mock.Mock()

    def test_security_groups_rule_updated(self):
        self.rpc.security_groups_rule_updated(None,
                                              security_groups=['fake_sgid'])
        self.rpc.sg_agent.assert_has_calls(
            [mock.call.security_groups_rule_updated(['fake_sgid'])])

    def test_security_groups_member_updated(self):
        self.rpc.security_groups_member_updated(None,
                                                security_groups=['fake_sgid'])
        self.rpc.sg_agent.assert_has_calls(
            [mock.call.security_groups_member_updated(['fake_sgid'])])

    def test_security_groups_provider_updated(self):
        self.rpc.security_groups_provider_updated(None)
        self.rpc.sg_agent.assert_has_calls(
            [mock.call.security_groups_provider_updated(None)])
