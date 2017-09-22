# Copyright (c) 2016 IBM Corp.
#
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

from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.tests import base


class RPCCallBackImpl(amb.CommonAgentManagerRpcCallBackBase):
    def security_groups_rule_updated(self, context, **kwargs):
        pass

    def security_groups_member_updated(self, context, **kwargs):
        pass


class Test_CommonAgentManagerRpcCallBackBase(base.BaseTestCase):
    def setUp(self):
        super(Test_CommonAgentManagerRpcCallBackBase, self).setUp()
        self.rpc_callbacks = RPCCallBackImpl(None, None, None)

    def test_get_and_clear_updated_devices(self):
        updated_devices = ['tap1', 'tap2']
        self.rpc_callbacks.updated_devices = updated_devices
        self.assertEqual(updated_devices,
                         self.rpc_callbacks.get_and_clear_updated_devices())
        self.assertEqual(set(), self.rpc_callbacks.updated_devices)

    def test_add_network(self):
        segment = amb.NetworkSegment('vlan', 'physnet1', 100)
        network_id = "foo"
        self.rpc_callbacks.add_network(network_id, segment)
        self.assertEqual(segment, self.rpc_callbacks.network_map[network_id])
