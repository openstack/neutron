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

import neutron.plugins.ml2.drivers.openvswitch.agent.common.constants \
    as ovs_const
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge_test_base


call = mock.call  # short hand


class OVSTunnelBridgeTest(ovs_bridge_test_base.OVSBridgeTestBase,
                          ovs_bridge_test_base.OVSDVRProcessTestMixin):
    dvr_process_table_id = ovs_const.DVR_PROCESS
    dvr_process_next_table_id = ovs_const.PATCH_LV_TO_TUN

    def setUp(self):
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        super(OVSTunnelBridgeTest, self).setUp()
        # NOTE(ivasilevskaya) The behaviour of oslotest.base.addCleanup()
        # according to https://review.openstack.org/#/c/119201/4 guarantees
        # that all started mocks will be stopped even without direct call to
        # patcher.stop().
        # If any individual mocks should be stopped by other than default
        # mechanism, their cleanup has to be added after
        # oslotest.BaseTestCase.setUp() not to be included in the stopall set
        # that will be cleaned up by mock.patch.stopall. This way the mock
        # won't be attempted to be stopped twice.
        self.addCleanup(conn_patcher.stop)
        self.setup_bridge_mock('br-tun', self.br_tun_cls)
        self.stamp = self.br.default_cookie

    def test_setup_default_table(self):
        patch_int_ofport = 5555
        arp_responder_enabled = False
        self.br.setup_default_table(patch_int_ofport=patch_int_ofport,
            arp_responder_enabled=arp_responder_enabled)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=2)],
                match=ofpp.OFPMatch(in_port=patch_int_ofport),
                priority=1, table_id=0),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0, table_id=0),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=20)],
                match=ofpp.OFPMatch(
                    eth_dst=('00:00:00:00:00:00', '01:00:00:00:00:00')),
                priority=0,
                table_id=2),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=22)],
                match=ofpp.OFPMatch(
                    eth_dst=('01:00:00:00:00:00', '01:00:00:00:00:00')),
                priority=0,
                table_id=2),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0, table_id=3),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0, table_id=4),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0, table_id=6),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.NXActionLearn(
                            cookie=self.stamp,
                            hard_timeout=300,
                            priority=1,
                            specs=[
                                ofpp.NXFlowSpecMatch(
                                    dst=('vlan_tci', 0),
                                    n_bits=12,
                                    src=('vlan_tci', 0)),
                                ofpp.NXFlowSpecMatch(
                                    dst=('eth_dst', 0),
                                    n_bits=48,
                                    src=('eth_src', 0)),
                                ofpp.NXFlowSpecLoad(
                                    dst=('vlan_tci', 0),
                                    n_bits=16,
                                    src=0),
                                ofpp.NXFlowSpecLoad(
                                    dst=('tunnel_id', 0),
                                    n_bits=64,
                                    src=('tunnel_id', 0)),
                                ofpp.NXFlowSpecOutput(
                                    dst='',
                                    n_bits=32,
                                    src=('in_port', 0)),
                            ],
                            table_id=20),
                        ofpp.OFPActionOutput(patch_int_ofport, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(),
                priority=1,
                table_id=10),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=22)],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=20),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=22),
                           active_bundle=None)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_setup_default_table_arp_responder_enabled(self):
        patch_int_ofport = 5555
        arp_responder_enabled = True
        self.br.setup_default_table(patch_int_ofport=patch_int_ofport,
            arp_responder_enabled=arp_responder_enabled)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=2)],
                match=ofpp.OFPMatch(in_port=patch_int_ofport),
                priority=1, table_id=0),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0, table_id=0),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=21)],
                match=ofpp.OFPMatch(
                    eth_dst='ff:ff:ff:ff:ff:ff',
                    eth_type=self.ether_types.ETH_TYPE_ARP),
                priority=1,
                table_id=2),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=20)],
                match=ofpp.OFPMatch(
                    eth_dst=('00:00:00:00:00:00', '01:00:00:00:00:00')),
                priority=0,
                table_id=2),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=22)],
                match=ofpp.OFPMatch(
                    eth_dst=('01:00:00:00:00:00', '01:00:00:00:00:00')),
                priority=0,
                table_id=2),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0, table_id=3),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0, table_id=4),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0, table_id=6),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.NXActionLearn(
                            cookie=self.stamp,
                            hard_timeout=300,
                            priority=1,
                            specs=[
                                ofpp.NXFlowSpecMatch(
                                    dst=('vlan_tci', 0),
                                    n_bits=12,
                                    src=('vlan_tci', 0)),
                                ofpp.NXFlowSpecMatch(
                                    dst=('eth_dst', 0),
                                    n_bits=48,
                                    src=('eth_src', 0)),
                                ofpp.NXFlowSpecLoad(
                                    dst=('vlan_tci', 0),
                                    n_bits=16,
                                    src=0),
                                ofpp.NXFlowSpecLoad(
                                    dst=('tunnel_id', 0),
                                    n_bits=64,
                                    src=('tunnel_id', 0)),
                                ofpp.NXFlowSpecOutput(
                                    dst='',
                                    n_bits=32,
                                    src=('in_port', 0)),
                            ],
                            table_id=20),
                        ofpp.OFPActionOutput(patch_int_ofport, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(),
                priority=1,
                table_id=10),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=22)],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=20),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[ofpp.OFPInstructionGotoTable(table_id=22)],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=21),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=22),
                           active_bundle=None)
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_provision_local_vlan(self):
        network_type = 'vxlan'
        lvid = 888
        segmentation_id = 777
        distributed = False
        self.br.provision_local_vlan(network_type=network_type, lvid=lvid,
                                     segmentation_id=segmentation_id,
                                     distributed=distributed)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPushVlan(),
                        ofpp.OFPActionSetField(
                            vlan_vid=lvid | ofp.OFPVID_PRESENT)
                    ]),
                    ofpp.OFPInstructionGotoTable(table_id=10),
                ],
                match=ofpp.OFPMatch(tunnel_id=segmentation_id),
                priority=1,
                table_id=4),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_reclaim_local_vlan(self):
        network_type = 'vxlan'
        segmentation_id = 777
        self.br.reclaim_local_vlan(network_type=network_type,
                                   segmentation_id=segmentation_id)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                table_id=4,
                match=ofpp.OFPMatch(tunnel_id=segmentation_id)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_flood_to_tun(self):
        vlan = 3333
        tun_id = 2222
        ports = [11, 44, 22, 33]
        self.br.install_flood_to_tun(vlan=vlan,
                                     tun_id=tun_id,
                                     ports=ports)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPopVlan(),
                        ofpp.OFPActionSetField(tunnel_id=tun_id),
                    ] + [ofpp.OFPActionOutput(p, 0) for p in ports]),
                ],
                match=ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT),
                priority=1,
                table_id=22),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_flood_to_tun(self):
        vlan = 3333
        self.br.delete_flood_to_tun(vlan=vlan)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(table_id=22,
                match=ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_unicast_to_tun(self):
        vlan = 3333
        port = 55
        mac = '08:60:6e:7f:74:e7'
        tun_id = 2222
        self.br.install_unicast_to_tun(vlan=vlan,
                                       tun_id=tun_id,
                                       port=port,
                                       mac=mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPopVlan(),
                        ofpp.OFPActionSetField(tunnel_id=tun_id),
                        ofpp.OFPActionOutput(port, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    eth_dst=mac, vlan_vid=vlan | ofp.OFPVID_PRESENT),
                priority=2,
                table_id=20),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_unicast_to_tun(self):
        vlan = 3333
        mac = '08:60:6e:7f:74:e7'
        self.br.delete_unicast_to_tun(vlan=vlan, mac=mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(table_id=20,
                match=ofpp.OFPMatch(
                    eth_dst=mac, vlan_vid=vlan | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_unicast_to_tun_without_mac(self):
        vlan = 3333
        mac = None
        self.br.delete_unicast_to_tun(vlan=vlan, mac=mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(table_id=20,
                match=ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_arp_responder(self):
        vlan = 3333
        ip = '192.0.2.1'
        mac = '08:60:6e:7f:74:e7'
        self.br.install_arp_responder(vlan=vlan, ip=ip, mac=mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(arp_op=self.arp.ARP_REPLY),
                        ofpp.NXActionRegMove(
                            dst_field='arp_tha',
                            n_bits=48,
                            src_field='arp_sha'),
                        ofpp.NXActionRegMove(
                            dst_field='arp_tpa',
                            n_bits=32,
                            src_field='arp_spa'),
                        ofpp.OFPActionSetField(arp_sha=mac),
                        ofpp.OFPActionSetField(arp_spa=ip),
                        ofpp.NXActionRegMove(src_field='eth_src',
                                             dst_field='eth_dst',
                                             n_bits=48),
                        ofpp.OFPActionSetField(eth_src=mac),
                        ofpp.OFPActionOutput(ofp.OFPP_IN_PORT, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    arp_tpa=ip,
                    vlan_vid=vlan | ofp.OFPVID_PRESENT),
                priority=1,
                table_id=21),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_arp_responder(self):
        vlan = 3333
        ip = '192.0.2.1'
        self.br.delete_arp_responder(vlan=vlan, ip=ip)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    arp_tpa=ip,
                    vlan_vid=vlan | ofp.OFPVID_PRESENT),
                table_id=21),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_arp_responder_without_ip(self):
        vlan = 3333
        ip = None
        self.br.delete_arp_responder(vlan=vlan, ip=ip)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                match=ofpp.OFPMatch(
                    eth_type=self.ether_types.ETH_TYPE_ARP,
                    vlan_vid=vlan | ofp.OFPVID_PRESENT),
                table_id=21),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_setup_tunnel_port(self):
        network_type = 'vxlan'
        port = 11111
        self.br.setup_tunnel_port(network_type=network_type, port=port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(table_id=4),
                ],
                match=ofpp.OFPMatch(in_port=port),
                priority=1,
                table_id=0),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_cleanup_tunnel_port(self):
        port = 11111
        self.br.cleanup_tunnel_port(port=port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(in_port=port),
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
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionOutput(port, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(eth_src=mac),
                priority=1,
                table_id=9),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_dvr_mac_tun(self):
        mac = '00:02:b3:13:fe:3d'
        self.br.remove_dvr_mac_tun(mac=mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(eth_src=mac, table_id=9),
        ]
        self.assertEqual(expected, self.mock.mock_calls)
