# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from neutron.openstack.common import importutils
import neutron.plugins.ofagent.agent.metadata as meta
from neutron.tests.unit.ofagent import ofa_test_base


class TestOFAgentFlows(ofa_test_base.OFATestBase):

    _MOD = 'neutron.plugins.ofagent.agent.flows'

    def setUp(self):
        super(TestOFAgentFlows, self).setUp()
        self.mod = importutils.import_module(self._MOD)
        self.br = self.mod.OFAgentIntegrationBridge()
        self.br.set_dp(self._mk_test_dp("dp"))

    def test_setup_default_table(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.setup_default_table()
        (dp, ofp, ofpp) = br._get_dp()
        arp = importutils.import_module('ryu.lib.packet.arp')
        ether = importutils.import_module('ryu.ofproto.ether')
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(), out_group=ofp.OFPG_ANY,
                 out_port=ofp.OFPP_ANY, priority=0, table_id=ofp.OFPTT_ALL)),
            call(ofpp.OFPFlowMod(dp, priority=0, table_id=0)),
            call(ofpp.OFPFlowMod(dp, priority=0, table_id=1)),
            call(ofpp.OFPFlowMod(dp, priority=0, table_id=2)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=7)],
                 priority=0, table_id=3)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=5)],
                 priority=0, table_id=4)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=6)],
                 priority=0, table_id=5)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                 [ofpp.OFPActionOutput(ofp.OFPP_CONTROLLER)])],
                 match=ofpp.OFPMatch(arp_op=arp.ARP_REQUEST,
                 eth_type=ether.ETH_TYPE_ARP), priority=1, table_id=6)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=7)],
                 priority=0, table_id=6)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=8)],
                 priority=0, table_id=7)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=9)],
                 priority=0, table_id=8)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=10)],
                 priority=0, table_id=9)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=11)],
                 priority=0, table_id=10)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=12)],
                 priority=0, table_id=11)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=13)],
                 priority=0, table_id=12)),
            call(ofpp.OFPFlowMod(dp, priority=0, table_id=13)),
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_install_arp_responder(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.install_arp_responder(table_id=99)
        (dp, ofp, ofpp) = br._get_dp()
        arp = importutils.import_module('ryu.lib.packet.arp')
        ether = importutils.import_module('ryu.ofproto.ether')
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                 [ofpp.OFPActionOutput(ofp.OFPP_CONTROLLER)])],
                 match=ofpp.OFPMatch(arp_op=arp.ARP_REQUEST,
                 eth_type=ether.ETH_TYPE_ARP), priority=1, table_id=99)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=100)],
                 priority=0, table_id=99)),
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_install_tunnel_output(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.install_tunnel_output(table_id=110, network=111,
                                     segmentation_id=112, ports=[113, 114],
                                     goto_next=True)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                 [ofpp.OFPActionSetField(tunnel_id=112),
                 ofpp.OFPActionOutput(port=113),
                 ofpp.OFPActionOutput(port=114)]),
                 ofpp.OFPInstructionGotoTable(table_id=111)],
                 match=ofpp.OFPMatch(metadata=
                 meta.mk_metadata(111, meta.LOCAL)),
                 priority=1, table_id=110))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_delete_tunnel_output(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.delete_tunnel_output(table_id=110, network=111)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(metadata=
                 meta.mk_metadata(111, meta.LOCAL)),
                 out_group=ofp.OFPG_ANY,
                 out_port=ofp.OFPP_ANY, priority=0, table_id=110))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_provision_tenant_tunnel(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.provision_tenant_tunnel(network_type="gre", network=150,
                                       segmentation_id=151)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionWriteMetadata(metadata=150,
                 metadata_mask=meta.NETWORK_MASK),
                 ofpp.OFPInstructionGotoTable(table_id=7)],
                 match=ofpp.OFPMatch(tunnel_id=151), priority=1, table_id=1))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_reclaim_tenant_tunnel(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.reclaim_tenant_tunnel(network_type="gre", network=150,
                                     segmentation_id=151)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(tunnel_id=151), out_group=ofp.OFPG_ANY,
                 out_port=ofp.OFPP_ANY, priority=0, table_id=1))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_provision_tenant_physnet(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.provision_tenant_physnet(network_type="vlan", network=150,
                                        segmentation_id=151, phys_port=99)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, instructions=[
                    ofpp.OFPInstructionWriteMetadata(metadata=150,
                        metadata_mask=meta.NETWORK_MASK),
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPopVlan()]),
                    ofpp.OFPInstructionGotoTable(table_id=3)],
                match=ofpp.OFPMatch(in_port=99,
                                    vlan_vid=151 | ofp.OFPVID_PRESENT),
                priority=1, table_id=0)),
            call(ofpp.OFPFlowMod(dp, instructions=[
                ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                    ofpp.OFPActionPushVlan(),
                    ofpp.OFPActionSetField(vlan_vid=151 | ofp.OFPVID_PRESENT),
                    ofpp.OFPActionOutput(port=99), ofpp.OFPActionPopVlan()]),
                ofpp.OFPInstructionGotoTable(table_id=13)],
                match=ofpp.OFPMatch(metadata=
                meta.mk_metadata(150, meta.LOCAL)),
                priority=1, table_id=12))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_reclaim_tenant_physnet(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.reclaim_tenant_physnet(network_type="vlan", network=150,
                                      segmentation_id=151, phys_port=99)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(in_port=99,
                     vlan_vid=151 | ofp.OFPVID_PRESENT),
                 out_group=ofp.OFPG_ANY, out_port=ofp.OFPP_ANY, priority=0,
                 table_id=0)),
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(metadata=meta.mk_metadata(150)),
                 out_group=ofp.OFPG_ANY, out_port=ofp.OFPP_ANY, priority=0,
                 table_id=12))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_check_in_port_add_tunnel_port(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.check_in_port_add_tunnel_port(network_type="gre", port=99)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp,
                 instructions=[ofpp.OFPInstructionGotoTable(table_id=1)],
                 match=ofpp.OFPMatch(in_port=99), priority=1, table_id=0))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_check_in_port_add_local_port(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.check_in_port_add_local_port(network=123, port=99)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp,
                 instructions=[
                     ofpp.OFPInstructionWriteMetadata(
                         metadata=meta.LOCAL | 123,
                         metadata_mask=meta.LOCAL | meta.NETWORK_MASK),
                     ofpp.OFPInstructionGotoTable(table_id=4)],
                 match=ofpp.OFPMatch(in_port=99), priority=1, table_id=0))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_check_in_port_delete_port(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.check_in_port_delete_port(port=99)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(in_port=99), out_group=ofp.OFPG_ANY,
                 out_port=ofp.OFPP_ANY, priority=0, table_id=0))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_local_flood_update(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.local_flood_update(network=1234, ports=[1, 2, 3],
                                  flood_unicast=True)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp,
                 instructions=[ofpp.OFPInstructionActions(
                     ofp.OFPIT_APPLY_ACTIONS, [
                         ofpp.OFPActionOutput(port=1),
                         ofpp.OFPActionOutput(port=2),
                         ofpp.OFPActionOutput(port=3)])],
                     match=ofpp.OFPMatch(metadata=meta.mk_metadata(1234)),
                 priority=1, table_id=13)),
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE_STRICT,
                 match=ofpp.OFPMatch(
                     eth_dst=('01:00:00:00:00:00', '01:00:00:00:00:00'),
                     metadata=meta.mk_metadata(1234)),
                 out_group=ofp.OFPG_ANY, out_port=ofp.OFPP_ANY, priority=1,
                 table_id=13))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_local_flood_delete(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.local_flood_delete(network=1234)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(metadata=meta.mk_metadata(1234)),
                 out_group=ofp.OFPG_ANY, out_port=ofp.OFPP_ANY, priority=0,
                 table_id=13))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_local_out_add_port(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.local_out_add_port(network=1234, port=7,
                                  mac='12:34:56:78:9a:bc')
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                 [ofpp.OFPActionOutput(port=7)])],
                 match=ofpp.OFPMatch(eth_dst="12:34:56:78:9a:bc",
                 metadata=meta.mk_metadata(1234)), priority=1, table_id=8))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_local_out_delete_port(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.local_out_delete_port(network=1234, mac='12:34:56:78:9a:bc')
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(eth_dst="12:34:56:78:9a:bc",
                 metadata=meta.mk_metadata(1234)), out_group=ofp.OFPG_ANY,
                 out_port=ofp.OFPP_ANY, priority=0, table_id=8))
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_arp_passthrough(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.arp_passthrough(network=1234, tpa='192.0.2.1')
        (dp, ofp, ofpp) = br._get_dp()
        arp = importutils.import_module('ryu.lib.packet.arp')
        ether = importutils.import_module('ryu.ofproto.ether')
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, idle_timeout=5,
                 instructions=[ofpp.OFPInstructionGotoTable(table_id=7)],
                 match=ofpp.OFPMatch(arp_op=arp.ARP_REQUEST,
                 arp_tpa="192.0.2.1", eth_type=ether.ETH_TYPE_ARP,
                 metadata=meta.mk_metadata(1234)), priority=1, table_id=5))
        ]
        sendmsg.assert_has_calls(expected_calls)
