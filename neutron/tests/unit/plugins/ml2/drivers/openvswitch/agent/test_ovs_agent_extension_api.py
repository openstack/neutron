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

from unittest import mock

from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_agt

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    .openflow.native import ovs_bridge_test_base as native_ovs_bridge_test_base

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base


class TestOVSAgentExtensionAPI(ovs_test_base.OVSOSKenTestBase):

    def setUp(self):
        super().setUp()
        self.br_int = self.br_int_cls("br-int")
        self.br_tun = self.br_tun_cls("br-tun")
        self.br_phys = {'br-phys1': self.br_phys_cls('br-phys1'),
                        'br-phys2': self.br_phys_cls('br-phys2')}

    def _test_bridge(self, orig_bridge, new_bridge):
        self.assertIsNotNone(new_bridge)
        self.assertEqual(orig_bridge.br_name, new_bridge.br_name)
        self.assertIn(new_bridge._default_cookie,
                      orig_bridge.reserved_cookies)
        self.assertNotEqual(orig_bridge._default_cookie,
                            new_bridge._default_cookie)

    def test_request_int_br(self):
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(
            self.br_int, self.br_tun, {'phys': self.br_phys['br-phys1']})
        new_int_br = agent_extension_api.request_int_br()
        self._test_bridge(self.br_int, new_int_br)

    def test_request_tun_br(self):
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(
            self.br_int, self.br_tun, {'phys': self.br_phys['br-phys1']})
        new_tun_br = agent_extension_api.request_tun_br()
        self._test_bridge(self.br_tun, new_tun_br)

    def test_request_tun_br_tunneling_disabled(self):
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(
            self.br_int, None, {'phys': self.br_phys['br-phys1']})
        self.assertIsNone(agent_extension_api.request_tun_br())

    def test_request_phys_brs(self):
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(
            self.br_int, self.br_tun,
            {'phys1': self.br_phys['br-phys1'],
             'phys2': self.br_phys['br-phys2']})
        for phys_br in agent_extension_api.request_phy_brs():
            self._test_bridge(self.br_phys[phys_br.br_name], phys_br)

    def test_request_physical_br(self):
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(
            self.br_int, self.br_tun,
            {'phys1': self.br_phys['br-phys1'],
             'phys2': self.br_phys['br-phys2']})
        phys_br = agent_extension_api.request_physical_br('phys1')
        self._test_bridge(self.br_phys[phys_br.br_name], phys_br)


class TestOVSCookieBridgeOSKen(native_ovs_bridge_test_base.OVSBridgeTestBase):

    def setUp(self):
        super().setUp()
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
                    table_id=0),
                active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)
