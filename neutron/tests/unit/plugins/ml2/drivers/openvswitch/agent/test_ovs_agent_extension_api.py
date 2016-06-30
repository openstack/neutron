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

from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import ovs_bridge
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_agt

from neutron.tests import base


class TestOVSAgentExtensionAPI(base.BaseTestCase):

    def setUp(self):
        super(base.BaseTestCase, self).setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.native.connection.Connection.start')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)
        self.br_int = ovs_bridge.OVSAgentBridge("br-int")
        self.br_tun = ovs_bridge.OVSAgentBridge("br-tun")

    def _test_bridge(self, orig_bridge, new_bridge):
        self.assertIsNotNone(new_bridge)
        self.assertEqual(orig_bridge.br_name, new_bridge.br_name)
        self.assertIn(new_bridge.default_cookie,
                      orig_bridge.reserved_cookies)
        self.assertNotEqual(orig_bridge.default_cookie,
                            new_bridge.default_cookie)

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


class TestOVSCookieBridge(base.DietTestCase):

    def setUp(self):
        super(TestOVSCookieBridge, self).setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.native.connection.Connection.start')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)
        self.bridge = ovs_bridge.OVSAgentBridge("br-foo")
        self.bridge.do_action_flows = mock.Mock()
        self.tested_bridge = ovs_ext_agt.OVSCookieBridge(self.bridge)

    def test_reserved(self):
        self.assertIn(self.tested_bridge.default_cookie,
                      self.bridge.reserved_cookies)

    def test_add_flow_without_cookie(self):
        self.tested_bridge.add_flow(in_port=1, actions="output:2")
        self.bridge.do_action_flows.assert_called_once_with(
            'add',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": self.tested_bridge.default_cookie}]
        )

    def test_mod_flow_without_cookie(self):
        self.tested_bridge.mod_flow(in_port=1, actions="output:2")
        self.bridge.do_action_flows.assert_called_once_with(
            'mod',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": str(self.tested_bridge.default_cookie) + '/-1'}]
        )

    def test_del_flows_without_cookie(self):
        self.tested_bridge.delete_flows(in_port=1)
        self.bridge.do_action_flows.assert_called_once_with(
            'del',
            [{"in_port": 1,
              "cookie": str(self.tested_bridge.default_cookie) + '/-1'}]
        )

    def test_add_flow_with_cookie(self):
        self.tested_bridge.add_flow(cookie=1234,
                                    in_port=1, actions="output:2")
        self.bridge.do_action_flows.assert_called_once_with(
            'add',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": 1234}]
        )

    def test_mod_flow_with_cookie(self):
        self.tested_bridge.mod_flow(cookie='1234',
                                    in_port=1, actions="output:2")
        self.bridge.do_action_flows.assert_called_once_with(
            'mod',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": str(1234) + '/-1'}]
        )

    def test_del_flows_with_cookie(self):
        self.tested_bridge.delete_flows(cookie=1234, in_port=1)
        self.bridge.do_action_flows.assert_called_once_with(
            'del',
            [{"in_port": 1,
              "cookie": str(1234) + '/-1'}]
        )

    def test_mod_flow_with_mask(self):
        self.tested_bridge.mod_flow(cookie='1234/3',
                                    in_port=1, actions="output:2")
        self.bridge.do_action_flows.assert_called_once_with(
            'mod',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": str(1234) + '/3'}]
        )

    def test_del_flows_with_mask(self):
        self.tested_bridge.delete_flows(cookie='1234/7', in_port=1)
        self.bridge.do_action_flows.assert_called_once_with(
            'del',
            [{"in_port": 1,
              "cookie": str(1234) + '/7'}]
        )


class TestOVSDeferredCookieBridge(base.DietTestCase):

    def setUp(self):
        super(TestOVSDeferredCookieBridge, self).setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.native.connection.Connection.start')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)
        self.bridge = ovs_bridge.OVSAgentBridge("br-foo")
        self.bridge.do_action_flows = mock.Mock()
        self.cookie_bridge = ovs_ext_agt.OVSCookieBridge(self.bridge)
        self.tested_bridge = self.cookie_bridge.deferred()

    def test_add_flow(self):
        self.tested_bridge.add_flow(in_port=1, actions="output:2")
        self.tested_bridge.apply_flows()
        self.bridge.do_action_flows.assert_called_once_with(
            'add',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": self.cookie_bridge.default_cookie}]
        )

    def test_mod_flow(self):
        self.tested_bridge.mod_flow(in_port=1, actions="output:2")
        self.tested_bridge.apply_flows()
        self.bridge.do_action_flows.assert_called_once_with(
            'mod',
            [{"in_port": 1,
              "actions": "output:2",
              "cookie": str(self.cookie_bridge.default_cookie) + '/-1'}]
        )

    def test_del_flows(self):
        self.tested_bridge.delete_flows(in_port=1)
        self.tested_bridge.apply_flows()
        self.bridge.do_action_flows.assert_called_once_with(
            'del',
            [{"in_port": 1,
              "cookie": str(self.cookie_bridge.default_cookie) + '/-1'}]
        )
