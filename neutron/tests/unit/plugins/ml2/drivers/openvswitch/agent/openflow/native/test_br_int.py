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

from unittest import mock

from neutron_lib import constants as p_const
from neutron_lib.plugins.ml2 import ovs_constants

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge_test_base


call = mock.call  # short hand

PACKET_RATE_LIMIT = ovs_constants.PACKET_RATE_LIMIT
BANDWIDTH_RATE_LIMIT = ovs_constants.BANDWIDTH_RATE_LIMIT


class OVSIntegrationBridgeTest(ovs_bridge_test_base.OVSBridgeTestBase):
    def setUp(self):
        super(OVSIntegrationBridgeTest, self).setUp()
        self.setup_bridge_mock('br-int', self.br_int_cls)
        self.stamp = self.br.default_cookie

    def test_setup_default_table(self):
        self.br.setup_default_table(enable_openflow_dhcp=True,
                                    enable_dhcpv6=True)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=23),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=0),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(
                        table_id=ovs_constants.TRANSIENT_TABLE),
                ],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=PACKET_RATE_LIMIT),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS, [
                            ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0)
                        ]),
                ],
                match=ofpp.OFPMatch(),
                priority=1,
                table_id=ovs_constants.TRANSIENT_TABLE),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=77)],
                match=ofpp.OFPMatch(eth_type=self.ether_types.ETH_TYPE_IP,
                                    ip_proto=self.in_proto.IPPROTO_UDP,
                                    ipv4_dst="255.255.255.255",
                                    udp_dst=67,
                                    udp_src=68),
                priority=101,
                table_id=ovs_constants.TRANSIENT_TABLE),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=77),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=78)],
                match=ofpp.OFPMatch(eth_type=self.ether_types.ETH_TYPE_IPV6,
                                    ip_proto=self.in_proto.IPPROTO_UDP,
                                    ipv6_dst="ff02::1:2",
                                    udp_dst=547,
                                    udp_src=546),
                priority=101,
                table_id=ovs_constants.TRANSIENT_TABLE),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=78),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=24),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(vlan_vid=ofp.OFPVID_PRESENT | 4095),
                priority=65535,
                table_id=0),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS, [
                            ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0)
                        ]),
                ],
                match=ofpp.OFPMatch(),
                priority=3,
                table_id=ovs_constants.TRANSIENT_EGRESS_TABLE),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(
                dp, cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=30),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(
                dp, cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=31),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_provision_local_vlan(self):
        port = 999
        lvid = 888
        segmentation_id = 777
        self.br.provision_local_vlan(port=port, lvid=lvid,
                                     segmentation_id=segmentation_id)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(
                            vlan_vid=lvid | ofp.OFPVID_PRESENT),
                    ]),
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(
                    in_port=port,
                    vlan_vid=segmentation_id | ofp.OFPVID_PRESENT),
                priority=3,
                table_id=0),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_provision_local_vlan_novlan(self):
        port = 999
        lvid = 888
        segmentation_id = None
        self.br.provision_local_vlan(port=port, lvid=lvid,
                                     segmentation_id=segmentation_id)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPushVlan(),
                        ofpp.OFPActionSetField(
                            vlan_vid=lvid | ofp.OFPVID_PRESENT),
                    ]),
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(
                    in_port=port,
                    vlan_vid=ofp.OFPVID_NONE),
                priority=3,
                table_id=0),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_reclaim_local_vlan(self):
        port = 999
        segmentation_id = 777
        self.br.reclaim_local_vlan(port=port, segmentation_id=segmentation_id)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                match=ofpp.OFPMatch(
                    in_port=port,
                    vlan_vid=segmentation_id | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_reclaim_local_vlan_novlan(self):
        port = 999
        segmentation_id = None
        self.br.reclaim_local_vlan(port=port, segmentation_id=segmentation_id)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                match=ofpp.OFPMatch(
                    in_port=port,
                    vlan_vid=ofp.OFPVID_NONE)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_to_src_mac(self):
        network_type = 'vxlan'
        vlan_tag = 1111
        gateway_mac = '08:60:6e:7f:74:e7'
        dst_mac = '00:02:b3:13:fe:3d'
        dst_port = 6666
        self.br.install_dvr_to_src_mac(network_type=network_type,
                                       vlan_tag=vlan_tag,
                                       gateway_mac=gateway_mac,
                                       dst_mac=dst_mac,
                                       dst_port=dst_port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(eth_src=gateway_mac),
                    ]),
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT),
                priority=20,
                table_id=1),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPopVlan(),
                        ofpp.OFPActionOutput(6666, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT),
                priority=20,
                table_id=ovs_constants.TRANSIENT_TABLE),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_to_src_mac(self):
        network_type = 'vxlan'
        vlan_tag = 1111
        dst_mac = '00:02:b3:13:fe:3d'
        self.br.delete_dvr_to_src_mac(network_type=network_type,
                                      vlan_tag=vlan_tag,
                                      dst_mac=dst_mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                strict=True,
                priority=20,
                table_id=1,
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
            call.uninstall_flows(
                strict=True,
                priority=20,
                table_id=ovs_constants.TRANSIENT_TABLE,
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_to_src_mac_vlan(self):
        network_type = 'vlan'
        vlan_tag = 1111
        gateway_mac = '08:60:6e:7f:74:e7'
        dst_mac = '00:02:b3:13:fe:3d'
        dst_port = 6666
        self.br.install_dvr_to_src_mac(network_type=network_type,
                                       vlan_tag=vlan_tag,
                                       gateway_mac=gateway_mac,
                                       dst_mac=dst_mac,
                                       dst_port=dst_port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(eth_src=gateway_mac),
                    ]),
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT),
                priority=20,
                table_id=2),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPopVlan(),
                        ofpp.OFPActionOutput(dst_port, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT),
                priority=20,
                table_id=ovs_constants.TRANSIENT_TABLE),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_to_src_mac_flat(self):
        network_type = 'flat'
        gateway_mac = '08:60:6e:7f:74:e7'
        dst_mac = '00:02:b3:13:fe:3d'
        dst_port = 6666
        self.br.install_dvr_to_src_mac(network_type=network_type,
                                       vlan_tag=None,
                                       gateway_mac=gateway_mac,
                                       dst_mac=dst_mac,
                                       dst_port=dst_port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(eth_src=gateway_mac),
                    ]),
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=ofp.OFPVID_NONE),
                priority=20,
                table_id=2),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionOutput(dst_port, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=ofp.OFPVID_NONE),
                priority=20,
                table_id=ovs_constants.TRANSIENT_TABLE),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_to_src_mac_vlan(self):
        network_type = 'vlan'
        vlan_tag = 1111
        dst_mac = '00:02:b3:13:fe:3d'
        self.br.delete_dvr_to_src_mac(network_type=network_type,
                                      vlan_tag=vlan_tag,
                                      dst_mac=dst_mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                strict=True,
                priority=20,
                table_id=2,
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
            call.uninstall_flows(
                strict=True,
                priority=20,
                table_id=ovs_constants.TRANSIENT_TABLE,
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_to_src_mac_flat(self):
        network_type = 'flat'
        vlan_tag = None
        dst_mac = '00:02:b3:13:fe:3d'
        self.br.delete_dvr_to_src_mac(network_type=network_type,
                                      vlan_tag=vlan_tag,
                                      dst_mac=dst_mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                strict=True,
                priority=20,
                table_id=2,
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=ofp.OFPVID_NONE)),
            call.uninstall_flows(
                strict=True,
                priority=20,
                table_id=ovs_constants.TRANSIENT_TABLE,
                match=ofpp.OFPMatch(
                    eth_dst=dst_mac,
                    vlan_vid=ofp.OFPVID_NONE)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_add_dvr_mac_physical(self):
        mac = '00:02:b3:13:fe:3d'
        port = 8888
        self.br.add_dvr_mac_physical(mac=mac, port=port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=2),
                ],
                match=ofpp.OFPMatch(
                    eth_src=mac,
                    in_port=port),
                priority=4,
                table_id=0),
                           active_bundle=None)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_dvr_mac_vlan(self):
        mac = '00:02:b3:13:fe:3d'
        self.br.remove_dvr_mac_vlan(mac=mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(eth_src=mac, table_id=0),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_add_dvr_mac_tun(self):
        mac = '00:02:b3:13:fe:3d'
        port = 8888
        self.br.add_dvr_mac_tun(mac=mac, port=port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=1),
                ],
                match=ofpp.OFPMatch(
                    eth_src=mac,
                    in_port=port),
                priority=2,
                table_id=0),
                           active_bundle=None)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_dvr_mac_tun(self):
        mac = '00:02:b3:13:fe:3d'
        port = 8888
        self.br.remove_dvr_mac_tun(mac=mac, port=port)
        expected = [
            call.uninstall_flows(eth_src=mac, in_port=port, table_id=0),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_icmpv6_na_spoofing_protection(self):
        port = 8888
        ip_addresses = ['2001:db8::1', 'fdf8:f53b:82e4::1/128']
        self.br.install_icmpv6_na_spoofing_protection(port, ip_addresses)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_IPV6,
                    icmpv6_type=self.icmpv6.ND_NEIGHBOR_ADVERT,
                    ip_proto=self.in_proto.IPPROTO_ICMPV6,
                    ipv6_nd_target='2001:db8::1',
                    in_port=8888,
                ),
                priority=2,
                table_id=24),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=PACKET_RATE_LIMIT),
                ],
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_IPV6,
                    icmpv6_type=self.icmpv6.ND_NEIGHBOR_ADVERT,
                    ip_proto=self.in_proto.IPPROTO_ICMPV6,
                    ipv6_nd_target='fdf8:f53b:82e4::1',
                    in_port=8888,
                ),
                priority=2,
                table_id=24),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=24),
                ],
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_IPV6,
                    icmpv6_type=self.icmpv6.ND_NEIGHBOR_ADVERT,
                    ip_proto=self.in_proto.IPPROTO_ICMPV6,
                    in_port=8888,
                ),
                priority=10,
                table_id=0),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_arp_spoofing_protection(self):
        port = 8888
        ip_addresses = ['192.0.2.1', '192.0.2.2/32']
        self.br.install_arp_spoofing_protection(port, ip_addresses)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=25),
                ],
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    arp_spa='192.0.2.1',
                    in_port=8888,
                ),
                priority=2,
                table_id=24),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=25),
                ],
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    arp_spa='192.0.2.2',
                    in_port=8888
                ),
                priority=2,
                table_id=24),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=24),
                ],
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    in_port=8888,
                ),
                priority=10,
                table_id=0),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_arp_spoofing_protection(self):
        port = 8888
        self.br.delete_arp_spoofing_protection(port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(table_id=0, match=ofpp.OFPMatch(
                eth_type=self.ether_types.ETH_TYPE_ARP,
                in_port=8888)),
            call.uninstall_flows(table_id=0, match=ofpp.OFPMatch(
                eth_type=self.ether_types.ETH_TYPE_IPV6,
                icmpv6_type=self.icmpv6.ND_NEIGHBOR_ADVERT,
                in_port=8888,
                ip_proto=self.in_proto.IPPROTO_ICMPV6)),
            call.uninstall_flows(table_id=24, in_port=port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def _test_set_allowed_macs_for_port(self, port, mac_addresses,
                                        allow_all=False):
        mock_dump_flows = mock.patch.object(self.br, 'dump_flows').start()
        mock_dump_flows.return_value = []

        self.br.set_allowed_macs_for_port(port, mac_addresses, allow_all)
        (dp, ofp, ofpp) = self._get_dp()
        expected = []
        if allow_all:
            expected += [
                call.uninstall_flows(
                    table_id=ovs_constants.LOCAL_SWITCHING,
                    in_port=port, strict=True, priority=9),
                call.uninstall_flows(
                    table_id=ovs_constants.MAC_SPOOF_TABLE,
                    in_port=port, strict=True, priority=2),
            ]
            self.assertEqual(expected, self.mock.mock_calls)
            return

        mac_addresses = mac_addresses or []
        for address in mac_addresses:
            expected.append(
                call._send_msg(ofpp.OFPFlowMod(dp,
                    cookie=self.stamp,
                    instructions=[
                        ofpp.OFPInstructionGotoTable(
                            table_id=ovs_constants.LOCAL_EGRESS_TABLE),
                    ],
                    match=ofpp.OFPMatch(
                        eth_src=address,
                        in_port=port,
                    ),
                    priority=2,
                    table_id=ovs_constants.MAC_SPOOF_TABLE),
                               active_bundle=None))

        expected.append(
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(
                        table_id=ovs_constants.MAC_SPOOF_TABLE),
                ],
                match=ofpp.OFPMatch(
                    in_port=port,
                ),
                priority=9,
                table_id=ovs_constants.LOCAL_SWITCHING),
                           active_bundle=None))
        self.assertEqual(expected, self.mock.mock_calls)

    def test_set_allowed_macs_for_port(self):
        self._test_set_allowed_macs_for_port(1, ["11:22:33:44:55:66"])

    def test_set_allowed_macs_for_port_allow_all(self):
        self._test_set_allowed_macs_for_port(None, None, allow_all=True)

    def _test_delete_dvr_dst_mac_for_arp(self, network_type):
        if network_type in (p_const.TYPE_VLAN, p_const.TYPE_FLAT):
            table_id = ovs_constants.DVR_TO_SRC_MAC_PHYSICAL
        else:
            table_id = ovs_constants.DVR_TO_SRC_MAC

        if network_type == p_const.TYPE_FLAT:
            vlan_tag = None
        else:
            vlan_tag = 1111
        gateway_mac = '00:02:b3:13:fe:3e'
        dvr_mac = '00:02:b3:13:fe:3f'
        rtr_port = 8888
        self.br.delete_dvr_dst_mac_for_arp(network_type=network_type,
                                           vlan_tag=vlan_tag,
                                           gateway_mac=gateway_mac,
                                           dvr_mac=dvr_mac,
                                           rtr_port=rtr_port)
        (dp, ofp, ofpp) = self._get_dp()
        if network_type == p_const.TYPE_FLAT:
            expected = [
                call.uninstall_flows(
                    strict=True,
                    priority=5,
                    table_id=table_id,
                    match=ofpp.OFPMatch(
                        eth_dst=dvr_mac,
                        vlan_vid=ofp.OFPVID_NONE)),
            ]
        else:
            expected = [
                call.uninstall_flows(
                    strict=True,
                    priority=5,
                    table_id=table_id,
                    match=ofpp.OFPMatch(
                        eth_dst=dvr_mac,
                        vlan_vid=vlan_tag | ofp.OFPVID_PRESENT)),
            ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_dst_mac_for_arp_vlan(self):
        self._test_delete_dvr_dst_mac_for_arp(network_type='vlan')

    def test_delete_dvr_dst_mac_for_arp_tunnel(self):
        self._test_delete_dvr_dst_mac_for_arp(network_type='vxlan')

    def test_delete_dvr_dst_mac_for_flat(self):
        self._test_delete_dvr_dst_mac_for_arp(network_type='flat')

    def test_list_meter_features(self):
        (dp, ofp, ofpp) = self._get_dp()
        self.br.list_meter_features()
        self.assertIn(
            call._send_msg(ofpp.OFPMeterFeaturesStatsRequest(dp, 0),
                           reply_cls=ofpp.OFPMeterFeaturesStatsReply),
            self.mock.mock_calls)

    def test_create_meter(self):
        meter_id = 1
        rate = 2
        burst = 0
        (dp, ofp, ofpp) = self._get_dp()
        self.br.create_meter(meter_id, rate)

        bands = [
            ofpp.OFPMeterBandDrop(rate=rate, burst_size=burst)]
        req = ofpp.OFPMeterMod(datapath=dp, command=ofp.OFPMC_ADD,
                               flags=ofp.OFPMF_PKTPS, meter_id=meter_id,
                               bands=bands)

        expected = [call._send_msg(req)]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_meter(self):
        meter_id = 1
        (dp, ofp, ofpp) = self._get_dp()
        self.br.delete_meter(meter_id)

        req = ofpp.OFPMeterMod(datapath=dp, command=ofp.OFPMC_DELETE,
                               flags=ofp.OFPMF_PKTPS, meter_id=meter_id)
        expected = [call._send_msg(req)]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_update_meter(self):
        meter_id = 1
        rate = 2
        burst = 0
        (dp, ofp, ofpp) = self._get_dp()
        self.br.update_meter(meter_id, rate)

        bands = [
            ofpp.OFPMeterBandDrop(rate=rate, burst_size=burst)]
        req = ofpp.OFPMeterMod(datapath=dp, command=ofp.OFPMC_MODIFY,
                               flags=ofp.OFPMF_PKTPS, meter_id=meter_id,
                               bands=bands)
        expected = [call._send_msg(req)]
        self.assertEqual(expected, self.mock.mock_calls)

    def _test_apply_meter_to_port(self, direction, mac,
                            in_port=None, local_vlan=None):
        meter_id = 1
        (dp, ofp, ofpp) = self._get_dp()
        self.br.apply_meter_to_port(meter_id, direction, mac,
                                    in_port, local_vlan)

        if direction == p_const.EGRESS_DIRECTION and in_port:
            match = ofpp.OFPMatch(in_port=in_port, eth_src=mac)
        elif direction == p_const.INGRESS_DIRECTION and local_vlan:
            vlan_vid = local_vlan | ofp.OFPVID_PRESENT
            match = ofpp.OFPMatch(vlan_vid=vlan_vid, eth_dst=mac)

        instructions = [
            ofpp.OFPInstructionMeter(meter_id, type_=ofp.OFPIT_METER),
            ofpp.OFPInstructionGotoTable(
                table_id=BANDWIDTH_RATE_LIMIT)]

        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=instructions,
                match=match,
                priority=100,
                table_id=PACKET_RATE_LIMIT),
                active_bundle=None)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_apply_meter_to_port_egress(self):
        self._test_apply_meter_to_port(p_const.EGRESS_DIRECTION,
                                       mac="00:02:b3:13:fe:3e",
                                       in_port=1)

    def test_apply_meter_to_port_ingress(self):
        self._test_apply_meter_to_port(p_const.INGRESS_DIRECTION,
                                       mac="00:02:b3:13:fe:3e",
                                       local_vlan=1)

    def _test_remove_meter_from_port(self, direction, mac,
                               in_port=None, local_vlan=None):
        (_dp, ofp, ofpp) = self._get_dp()
        self.br.remove_meter_from_port(direction,
                                       mac, in_port, local_vlan)

        if direction == p_const.EGRESS_DIRECTION and in_port:
            match = ofpp.OFPMatch(in_port=in_port, eth_src=mac)
        elif direction == p_const.INGRESS_DIRECTION and local_vlan:
            vlan_vid = local_vlan | ofp.OFPVID_PRESENT
            match = ofpp.OFPMatch(vlan_vid=vlan_vid, eth_dst=mac)

        expected = [
            call.uninstall_flows(
                    table_id=PACKET_RATE_LIMIT,
                    match=match)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_meter_from_port_egress(self):
        self._test_remove_meter_from_port(p_const.EGRESS_DIRECTION,
                                          mac="00:02:b3:13:fe:3e",
                                          in_port=1)

    def test_remove_meter_from_port_ingress(self):
        self._test_remove_meter_from_port(p_const.INGRESS_DIRECTION,
                                          mac="00:02:b3:13:fe:3e",
                                          local_vlan=1)

    def test_install_dscp_marking_rule(self):
        test_port = 8888
        test_mark = 38
        self.br.install_dscp_marking_rule(port=test_port, dscp_mark=test_mark)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp, cookie=self.br.default_cookie,
                           instructions=[ofpp.OFPInstructionActions(
                               ofp.OFPIT_APPLY_ACTIONS,
                               [ofpp.OFPActionSetField(reg2=1),
                                ofpp.OFPActionSetField(ip_dscp=38),
                                ofpp.NXActionResubmit(in_port=8888)])],
                               match=ofpp.OFPMatch(eth_type=0x0800,
                                                   in_port=8888, reg2=0),
                               priority=65535, table_id=0),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp, cookie=self.br.default_cookie,
                           instructions=[ofpp.OFPInstructionActions(
                               ofp.OFPIT_APPLY_ACTIONS,
                               [ofpp.OFPActionSetField(reg2=1),
                                ofpp.OFPActionSetField(ip_dscp=38),
                                ofpp.NXActionResubmit(in_port=8888)])],
                               match=ofpp.OFPMatch(eth_type=0x86DD,
                                                   in_port=8888, reg2=0),
                               priority=65535, table_id=0),
                           active_bundle=None)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_setup_local_egress_flows(self):
        in_port = 10
        vlan = 3333
        self.br.setup_local_egress_flows(in_port=in_port, vlan=vlan)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp, cookie=self.stamp,
                               instructions=[
                                   ofpp.OFPInstructionGotoTable(table_id=30)],
                               match=ofpp.OFPMatch(in_port=in_port),
                               priority=8,
                               table_id=0),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp, cookie=self.stamp,
                               instructions=[ofpp.OFPInstructionActions(
                                   ofp.OFPIT_APPLY_ACTIONS,
                                   [ofpp.OFPActionSetField(reg6=vlan),
                                    ofpp.NXActionResubmitTable(in_port=in_port,
                                                               table_id=31)])],
                               match=ofpp.OFPMatch(in_port=in_port),
                               priority=10, table_id=30),
                           active_bundle=None)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_setup_local_egress_flows_ofport_invalid(self):
        in_port = ovs_constants.OFPORT_INVALID
        vlan = 3333
        self.br.setup_local_egress_flows(in_port=in_port, vlan=vlan)

        self.assertFalse(self.mock.called)

    def test_install_garp_blocker(self):
        vlan = 2222
        ip = '192.0.0.10'
        self.br.install_garp_blocker(vlan, ip)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp, cookie=self.stamp,
                               instructions=[],
                               match=ofpp.OFPMatch(
                                   vlan_vid=vlan | ofp.OFPVID_PRESENT,
                                   eth_type=self.ether_types.ETH_TYPE_ARP,
                                   arp_spa=ip),
                               priority=10,
                               table_id=0),
                           active_bundle=None)]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_garp_blocker(self):
        vlan = 2222
        ip = '192.0.0.10'
        self.br.delete_garp_blocker(vlan, ip)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                table_id=0,
                priority=10,
                match=ofpp.OFPMatch(
                    vlan_vid=vlan | ofp.OFPVID_PRESENT,
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    arp_spa=ip))
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_garp_blocker_exception(self):
        vlan = 2222
        ip = '192.0.0.10'
        except_ip = '192.0.0.20'
        self.br.install_garp_blocker_exception(vlan, ip, except_ip)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp, cookie=self.stamp,
                               instructions=[
                                   ofpp.OFPInstructionGotoTable(
                                       table_id=PACKET_RATE_LIMIT)],
                               match=ofpp.OFPMatch(
                                   vlan_vid=vlan | ofp.OFPVID_PRESENT,
                                   eth_type=self.ether_types.ETH_TYPE_ARP,
                                   arp_spa=ip, arp_tpa=except_ip),
                               priority=11,
                               table_id=0),
                           active_bundle=None)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_garp_blocker_exception(self):
        vlan = 2222
        ip = '192.0.0.10'
        except_ip = '192.0.0.20'
        self.br.delete_garp_blocker_exception(vlan, ip, except_ip)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                table_id=0,
                priority=11,
                match=ofpp.OFPMatch(
                    vlan_vid=vlan | ofp.OFPVID_PRESENT,
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    arp_spa=ip, arp_tpa=except_ip))
        ]
        self.assertEqual(expected, self.mock.mock_calls)
