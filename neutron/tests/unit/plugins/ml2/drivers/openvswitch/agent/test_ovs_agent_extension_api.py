# Copyright 2012 VMware, Inc.
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
#

import mock

from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_agt

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    .openflow.native import ovs_bridge_test_base as native_ovs_bridge_test_base

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base


class TestOVSAgentExtensionAPI(ovs_test_base.OVSOFCtlTestBase):

    def setUp(self):
        super(TestOVSAgentExtensionAPI, self).setUp()
        self.br_int = self.br_int_cls("br-int")
        self.br_tun = self.br_tun_cls("br-tun")

    def _test_bridge(self, orig_bridge, new_bridge):
        self.assertIsNotNone(new_bridge)
        self.assertEqual(orig_bridge.br_name, new_bridge.br_name)
        self.assertIn(new_bridge._default_cookie,
                      orig_bridge.reserved_cookies)
        self.assertNotEqual(orig_bridge._default_cookie,
                            new_bridge._default_cookie)

    def test_request_int_br(self):
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(self.br_int,
                                                               self.br_tun)
        new_int_br = agent_extension_api.request_int_br()
        self._test_bridge(self.br_int, new_int_br)

    def test_request_tun_br(self):
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(self.br_int,
                                                               self.br_tun)
        new_tun_br = agent_extension_api.request_tun_br()
        self._test_bridge(self.br_tun, new_tun_br)

    def test_request_tun_br_tunneling_disabled(self):
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(self.br_int,
                                                               None)
        self.assertIsNone(agent_extension_api.request_tun_br())


class TestOVSCookieBridgeOFCtl(ovs_test_base.OVSOFCtlTestBase):

    def setUp(self):
        super(TestOVSCookieBridgeOFCtl, self).setUp()
        self.bridge = self.br_int_cls("br-int")
        mock.patch.object(self.bridge, "run_ofctl").start()

        self.tested_bridge = ovs_ext_agt.OVSCookieBridge(self.bridge)

        # mocking do_action_flows does not work, because this method is
        # later wrapped by the cookie bridge code, and six.wraps apparently
        # can't wrap a mock, so we mock deeper
        self.mock_build_flow_expr_str = mock.patch(
            'neutron.agent.common.ovs_lib._build_flow_expr_str',
            return_value="").start()

    def test_cookie(self):
        self.assertNotEqual(self.bridge._default_cookie,
                            self.tested_bridge._default_cookie)

    def test_reserved(self):
        self.assertIn(self.tested_bridge._default_cookie,
                      self.bridge.reserved_cookies)

    def assert_mock_build_flow_expr_str_call(self, action, kwargs_list,
                                             strict=False):
        self.mock_build_flow_expr_str.assert_called_once_with(
            kwargs_list[0],
            action,
            strict
        )

    def test_add_flow_without_cookie(self):
        self.tested_bridge.add_flow(in_port=1, actions="output:2")
        self.assert_mock_build_flow_expr_str_call(
            'add',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": self.tested_bridge._default_cookie}]
        )

    def test_mod_flow_without_cookie(self):
        self.tested_bridge.mod_flow(in_port=1, actions="output:2")
        self.assert_mock_build_flow_expr_str_call(
            'mod',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": self.tested_bridge._default_cookie}]
        )

    def test_del_flows_without_cookie(self):
        self.tested_bridge.delete_flows(in_port=1)
        self.assert_mock_build_flow_expr_str_call(
            'del',
            [{"in_port": 1,
              "cookie": str(self.tested_bridge._default_cookie) + '/-1'}]
        )

    def test_add_flow_with_cookie(self):
        self.tested_bridge.add_flow(cookie=1234,
                                    in_port=1, actions="output:2")
        self.assert_mock_build_flow_expr_str_call(
            'add',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": 1234}]
        )

    def test_mod_flow_with_cookie(self):
        self.tested_bridge.mod_flow(cookie='1234',
                                    in_port=1, actions="output:2")
        self.assert_mock_build_flow_expr_str_call(
            'mod',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": "1234"}]
        )

    def test_del_flows_with_cookie(self):
        self.tested_bridge.delete_flows(cookie=1234, in_port=1)
        self.assert_mock_build_flow_expr_str_call(
            'del',
            [{"in_port": 1,
              "cookie": "1234/-1"}]
        )

    def test_mod_flow_with_cookie_mask(self):
        self.tested_bridge.mod_flow(cookie='1234/3',
                                    in_port=1, actions="output:2")
        self.assert_mock_build_flow_expr_str_call(
            'mod',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": str(1234) + '/3'}]
        )

    def test_del_flows_with_cookie_mask(self):
        self.tested_bridge.delete_flows(cookie='1234/7', in_port=1)
        self.assert_mock_build_flow_expr_str_call(
            'del',
            [{"in_port": 1,
              "cookie": str(1234) + '/7'}]
        )

    def test_install_drop(self):
        self.tested_bridge.install_drop()
        self.assert_mock_build_flow_expr_str_call(
            'add',
            [{"table": 0,
              "priority": 0,
              "actions": "drop",
              "cookie": self.tested_bridge._default_cookie}]
        )


class TestOVSCookieBridgeRyu(native_ovs_bridge_test_base.OVSBridgeTestBase):

    def setUp(self):
        super(TestOVSCookieBridgeRyu, self).setUp()
        self.setup_bridge_mock('br-int', self.br_int_cls)
        self.tested_bridge = ovs_ext_agt.OVSCookieBridge(self.br)

    def test_cookie(self):
        self.assertNotEqual(self.br._default_cookie,
                            self.tested_bridge._default_cookie)

    def test_reserved(self):
        self.assertIn(self.tested_bridge._default_cookie,
                      self.br.reserved_cookies)

    def test_install_drop(self):
        priority = 99
        in_port = 666
        self.tested_bridge.install_drop(priority=priority,
                                        in_port=in_port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            mock.call._send_msg(
                ofpp.OFPFlowMod(
                    dp,
                    # this is the interesting part of the check:
                    cookie=self.tested_bridge._default_cookie,
                    instructions=[],
                    match=ofpp.OFPMatch(in_port=in_port),
                    priority=priority,
                    table_id=0)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)
