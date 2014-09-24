# Copyright 2013 NEC Corporation.  All rights reserved.
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

from neutron.api.rpc.handlers import l3_rpc
from neutron.common import constants
from neutron.tests.unit.nec import test_nec_plugin
from neutron.tests.unit.openvswitch import test_agent_scheduler

L3_HOSTA = test_agent_scheduler.L3_HOSTA
L3_HOSTB = test_agent_scheduler.L3_HOSTB


class NecAgentSchedulerTestCase(
    test_agent_scheduler.OvsAgentSchedulerTestCase,
    test_nec_plugin.NecPluginV2TestCaseBase):

    plugin_str = test_nec_plugin.PLUGIN_NAME
    l3_plugin = None

    def setUp(self):
        self.setup_nec_plugin_base()
        super(NecAgentSchedulerTestCase, self).setUp()


class NecDhcpAgentNotifierTestCase(
    test_agent_scheduler.OvsDhcpAgentNotifierTestCase,
    test_nec_plugin.NecPluginV2TestCaseBase):

    plugin_str = test_nec_plugin.PLUGIN_NAME
    l3_plugin = None

    def setUp(self):
        self.setup_nec_plugin_base()
        super(NecDhcpAgentNotifierTestCase, self).setUp()


class NecL3AgentNotifierTestCase(
    test_agent_scheduler.OvsL3AgentNotifierTestCase,
    test_nec_plugin.NecPluginV2TestCaseBase):

    plugin_str = test_nec_plugin.PLUGIN_NAME
    l3_plugin = None

    def setUp(self):
        self.setup_nec_plugin_base()
        super(NecL3AgentNotifierTestCase, self).setUp()


class NecL3AgentSchedulerWithOpenFlowRouter(
    test_agent_scheduler.OvsAgentSchedulerTestCaseBase,
    test_nec_plugin.NecPluginV2TestCaseBase):

    plugin_str = test_nec_plugin.PLUGIN_NAME
    l3_plugin = None

    def setUp(self):
        self.setup_nec_plugin_base()
        super(NecL3AgentSchedulerWithOpenFlowRouter, self).setUp()

    def test_router_auto_schedule_with_l3agent_and_openflow(self):
        with contextlib.nested(
            self.router(),
            self.router(arg_list=('provider',),
                        provider='openflow'
                        )) as (r1, r2):
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()
            ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA)
            ret_b = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTB)
            l3_agents = self._list_l3_agents_hosting_router(
                r1['router']['id'])
            self.assertEqual(1, len(ret_a))
            self.assertFalse(len(ret_b))
            self.assertIn(r1['router']['id'], [r['id'] for r in ret_a])
            self.assertNotIn(r2['router']['id'], [r['id'] for r in ret_a])
        self.assertEqual(1, len(l3_agents['agents']))
        self.assertEqual(L3_HOSTA, l3_agents['agents'][0]['host'])

    def test_router_auto_schedule_only_with_openflow_router(self):
        with contextlib.nested(
            self.router(arg_list=('provider',), provider='openflow'),
            self.router(arg_list=('provider',), provider='openflow')
        ) as (r1, r2):
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()
            ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA)
            l3_agents_1 = self._list_l3_agents_hosting_router(
                r1['router']['id'])
            l3_agents_2 = self._list_l3_agents_hosting_router(
                r2['router']['id'])
            self.assertFalse(len(ret_a))
            self.assertNotIn(r1['router']['id'], [r['id'] for r in ret_a])
            self.assertNotIn(r2['router']['id'], [r['id'] for r in ret_a])
        self.assertFalse(len(l3_agents_1['agents']))
        self.assertFalse(len(l3_agents_2['agents']))

    def test_add_router_to_l3_agent_for_openflow_router(self):
        with self.router(arg_list=('provider',), provider='openflow') as r1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._add_router_to_l3_agent(hosta_id,
                                         r1['router']['id'],
                                         expected_code=409)
