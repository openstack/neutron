# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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
from oslo_utils import importutils

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base


call = mock.call  # short hand


class OVSBridgeTestBase(ovs_test_base.OVSOSKenTestBase):
    _ARP_MODULE = 'os_ken.lib.packet.arp'
    _ETHER_TYPES_MODULE = 'os_ken.lib.packet.ether_types'
    _ICMPV6_MODULE = 'os_ken.lib.packet.icmpv6'
    _IN_PROTO_MODULE = 'os_ken.lib.packet.in_proto'
    _OFP_MODULE = 'os_ken.ofproto.ofproto_v1_3'
    _OFPP_MODULE = 'os_ken.ofproto.ofproto_v1_3_parser'

    def setup_bridge_mock(self, name, cls):
        self.br = cls(name)
        self.stamp = self.br.default_cookie
        self.dp = mock.Mock()
        self.ofp = importutils.import_module(self._OFP_MODULE)
        self.ofpp = importutils.import_module(self._OFPP_MODULE)
        self.arp = importutils.import_module(self._ARP_MODULE)
        self.ether_types = importutils.import_module(self._ETHER_TYPES_MODULE)
        self.icmpv6 = importutils.import_module(self._ICMPV6_MODULE)
        self.in_proto = importutils.import_module(self._IN_PROTO_MODULE)
        mock.patch.object(self.br, '_get_dp', autospec=True,
                          return_value=self._get_dp()).start()
        mock__send_msg = mock.patch.object(self.br, '_send_msg').start()
        mock_delete_flows = mock.patch.object(self.br,
                                              'uninstall_flows').start()
        self.mock = mock.Mock()
        self.mock.attach_mock(mock__send_msg, '_send_msg')
        self.mock.attach_mock(mock_delete_flows, 'uninstall_flows')

    def _get_dp(self):
        return self.dp, self.ofp, self.ofpp

    def test_drop_port(self):
        in_port = 2345
        self.br.drop_port(in_port=in_port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(
                ofpp.OFPFlowMod(dp,
                    cookie=self.stamp,
                    instructions=[],
                    match=ofpp.OFPMatch(in_port=in_port),
                    priority=2,
                    table_id=0),
                active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_goto(self):
        dest_table_id = 123
        priority = 99
        in_port = 666
        self.br.install_goto(dest_table_id=dest_table_id,
                             priority=priority, in_port=in_port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(
                ofpp.OFPFlowMod(dp,
                    cookie=self.stamp,
                    instructions=[
                        ofpp.OFPInstructionGotoTable(table_id=dest_table_id),
                    ],
                    match=ofpp.OFPMatch(in_port=in_port),
                    priority=priority,
                    table_id=0),
                active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_drop(self):
        priority = 99
        in_port = 666
        self.br.install_drop(priority=priority, in_port=in_port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(
                ofpp.OFPFlowMod(dp,
                    cookie=self.stamp,
                    instructions=[],
                    match=ofpp.OFPMatch(in_port=in_port),
                    priority=priority,
                    table_id=0),
                active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_normal(self):
        priority = 99
        in_port = 666
        self.br.install_normal(priority=priority, in_port=in_port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(
                ofpp.OFPFlowMod(dp,
                    cookie=self.stamp,
                    instructions=[
                        ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                            ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0)
                        ]),
                    ],
                    match=ofpp.OFPMatch(in_port=in_port),
                    priority=priority,
                    table_id=0),
                active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test__cidr_to_os_ken(self):
        f = self.br._cidr_to_os_ken
        self.assertEqual('192.168.0.1', f('192.168.0.1'))
        self.assertEqual('192.168.0.1', f('192.168.0.1/32'))
        self.assertEqual(('192.168.0.0', '255.255.255.0'), f('192.168.0.0/24'))

    def test__setup_controllers__out_of_band(self):
        cfg = mock.MagicMock()
        cfg.OVS.of_listen_address = ""
        cfg.OVS.of_listen_port = ""

        m_add_protocols = mock.patch.object(self.br, 'add_protocols')
        m_set_controller = mock.patch.object(self.br, 'set_controller')
        m_set_ccm = mock.patch.object(self.br,
                                      'set_controllers_connection_mode')

        with m_set_ccm as set_ccm, m_set_controller, m_add_protocols:
            self.br.setup_controllers(cfg)
            set_ccm.assert_called_once_with("out-of-band")


class OVSDVRProcessTestMixin(object):
    def test_install_dvr_process_ipv4(self):
        vlan_tag = 999
        gateway_ip = '192.0.2.1'
        self.br.install_dvr_process_ipv4(vlan_tag=vlan_tag,
                                         gateway_ip=gateway_ip)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    arp_tpa=gateway_ip,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT),
                priority=3,
                table_id=self.dvr_process_table_id),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_process_ipv4(self):
        vlan_tag = 999
        gateway_ip = '192.0.2.1'
        self.br.delete_dvr_process_ipv4(vlan_tag=vlan_tag,
                                        gateway_ip=gateway_ip)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(table_id=self.dvr_process_table_id,
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    arp_tpa=gateway_ip,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_process_ipv6(self):
        vlan_tag = 999
        gateway_mac = '08:60:6e:7f:74:e7'
        self.br.install_dvr_process_ipv6(vlan_tag=vlan_tag,
                                         gateway_mac=gateway_mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(
                    eth_src=gateway_mac,
                    eth_type=self.ether_types.ETH_TYPE_IPV6,
                    icmpv6_type=self.icmpv6.ND_ROUTER_ADVERT,
                    ip_proto=self.in_proto.IPPROTO_ICMPV6,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT),
                priority=3,
                table_id=self.dvr_process_table_id),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_process_ipv6(self):
        vlan_tag = 999
        gateway_mac = '08:60:6e:7f:74:e7'
        self.br.delete_dvr_process_ipv6(vlan_tag=vlan_tag,
                                        gateway_mac=gateway_mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(table_id=self.dvr_process_table_id,
                match=ofpp.OFPMatch(
                    eth_src=gateway_mac,
                    eth_type=self.ether_types.ETH_TYPE_IPV6,
                    icmpv6_type=self.icmpv6.ND_ROUTER_ADVERT,
                    ip_proto=self.in_proto.IPPROTO_ICMPV6,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_process(self):
        vlan_tag = 999
        vif_mac = '00:0e:0c:5e:95:d0'
        dvr_mac_address = 'f2:0b:a4:5b:b2:ab'
        self.br.install_dvr_process(vlan_tag=vlan_tag,
                                    vif_mac=vif_mac,
                                    dvr_mac_address=dvr_mac_address)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(
                    eth_dst=vif_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT),
                priority=2,
                table_id=self.dvr_process_table_id),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(eth_src=dvr_mac_address),
                    ]),
                    ofpp.OFPInstructionGotoTable(
                        table_id=self.dvr_process_next_table_id),
                ],
                match=ofpp.OFPMatch(
                    eth_src=vif_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT),
                priority=1,
                table_id=self.dvr_process_table_id),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_process(self):
        vlan_tag = 999
        vif_mac = '00:0e:0c:5e:95:d0'
        self.br.delete_dvr_process(vlan_tag=vlan_tag,
                                   vif_mac=vif_mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(table_id=self.dvr_process_table_id,
                match=ofpp.OFPMatch(
                    eth_dst=vif_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
            call.uninstall_flows(table_id=self.dvr_process_table_id,
                match=ofpp.OFPMatch(
                    eth_src=vif_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)
