# Copyright (c) 2023 China Unicom Cloud Data Co.,Ltd.
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

from neutron_lib.plugins.ml2 import ovs_constants as p_const

from os_ken.lib.packet import ether_types
from os_ken.lib.packet import in_proto

from neutron.agent.l2.extensions.metadata import metadata_flows_process
from neutron.agent.l2.extensions.metadata import metadata_path
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge_test_base

call = mock.call  # short hand


class MetadataDataPathFlowsTestCase(ovs_bridge_test_base.OVSBridgeTestMixin):

    def setUp(self):
        super().setUp()
        self.int_br = self.mock_bridge_cls('br-int', self.br_int_cls)
        self.path_br = self.mock_bridge_cls('br-phys', self.br_phys_cls)
        self.flows = metadata_flows_process.MetadataDataPathFlows()
        self.flows.set_path_br(self.path_br)
        self.flows.int_br = self.int_br
        self.provider_gateway_ip = "1.1.1.1"
        self.metadata_host_info = {
            "gateway_ip": self.provider_gateway_ip,
            "provider_ip": self.provider_gateway_ip,
            "mac_address": metadata_path.DEFAULT_META_GATEWAY_MAC,
            "service_protocol_port": 55555}

        mock__send_msg = mock.patch.object(self.int_br, '_send_msg').start()
        mock_delete_flows = mock.patch.object(self.int_br,
                                              'uninstall_flows').start()
        self.int_br.mock = mock.Mock()
        self.int_br.mock.attach_mock(mock__send_msg, '_send_msg')
        self.int_br.mock.attach_mock(mock_delete_flows, 'uninstall_flows')

    def test_metadata_path_defaults(self):
        provider_vlan = 1000
        ofport_patch_meta_to_int = 100
        ofport_tap_meta = 200
        self.flows.metadata_path_defaults(
            provider_vlan, ofport_patch_meta_to_int,
            ofport_tap_meta, self.metadata_host_info)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=p_const.METADATA_EGRESS_NAT),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=p_const.METADATA_IP_ARP_RESPONDER),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=p_const.METADATA_INGRESS_DIRECT),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(
                        table_id=p_const.METADATA_EGRESS_NAT),
                ],
                match=ofpp.OFPMatch(
                    in_port=ofport_patch_meta_to_int,
                    ipv4_dst=metadata_flows_process.METADATA_V4_IP,
                    eth_type=ether_types.ETH_TYPE_IP),
                priority=201,
                table_id=p_const.LOCAL_SWITCHING),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPushVlan(),
                        ofpp.OFPActionSetField(
                            vlan_vid=provider_vlan | ofp.OFPVID_PRESENT),
                    ]),
                    ofpp.OFPInstructionGotoTable(
                        table_id=p_const.METADATA_INGRESS_DIRECT),
                ],
                match=ofpp.OFPMatch(
                    in_port=ofport_tap_meta,
                    eth_type=ether_types.ETH_TYPE_IP),
                priority=201,
                table_id=p_const.LOCAL_SWITCHING),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(
                            eth_dst=metadata_path.DEFAULT_META_GATEWAY_MAC),
                        ofpp.OFPActionSetField(
                            ipv4_dst=self.provider_gateway_ip),
                        ofpp.OFPActionSetField(tcp_dst=55555),
                        ofpp.OFPActionOutput(ofport_tap_meta, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=metadata_flows_process.METADATA_V4_IP,
                    tcp_dst=80,
                    ip_proto=in_proto.IPPROTO_TCP),
                priority=202,
                table_id=p_const.METADATA_EGRESS_OUTPUT),
                           active_bundle=None),
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(
                        table_id=p_const.METADATA_IP_ARP_RESPONDER),
                ],
                match=ofpp.OFPMatch(
                    in_port=ofport_tap_meta,
                    eth_type=ether_types.ETH_TYPE_ARP),
                priority=201,
                table_id=p_const.LOCAL_SWITCHING),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_metadata_egress_direct(self):
        ofport_patch_meta_to_int = 100
        self.flows.metadata_egress_direct(ofport_patch_meta_to_int)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(
                        table_id=p_const.METADATA_EGRESS_NAT),
                ],
                match=ofpp.OFPMatch(
                    in_port=ofport_patch_meta_to_int,
                    ipv4_dst=metadata_flows_process.METADATA_V4_IP,
                    eth_type=ether_types.ETH_TYPE_IP),
                priority=201,
                table_id=p_const.LOCAL_SWITCHING),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_metadata_ingress_direct(self):
        provider_vlan = 1000
        ofport_tap_meta = 200
        self.flows.metadata_ingress_direct(
            provider_vlan, ofport_tap_meta)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPushVlan(),
                        ofpp.OFPActionSetField(
                            vlan_vid=provider_vlan | ofp.OFPVID_PRESENT),
                    ]),
                    ofpp.OFPInstructionGotoTable(
                        table_id=p_const.METADATA_INGRESS_DIRECT),
                ],
                match=ofpp.OFPMatch(
                    in_port=ofport_tap_meta,
                    eth_type=ether_types.ETH_TYPE_IP),
                priority=201,
                table_id=p_const.LOCAL_SWITCHING),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_metadata_arp_direct(self):
        ofport_tap_meta = 200
        self.flows.metadata_arp_direct(ofport_tap_meta)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionGotoTable(
                        table_id=p_const.METADATA_IP_ARP_RESPONDER),
                ],
                match=ofpp.OFPMatch(
                    in_port=ofport_tap_meta,
                    eth_type=ether_types.ETH_TYPE_ARP),
                priority=201,
                table_id=p_const.LOCAL_SWITCHING),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_metadata_path_classify(self):
        ofport_tap_meta = 200
        self.flows.metadata_path_classify(
            ofport_tap_meta, self.metadata_host_info)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(
                            eth_dst=metadata_path.DEFAULT_META_GATEWAY_MAC),
                        ofpp.OFPActionSetField(
                            ipv4_dst=self.provider_gateway_ip),
                        ofpp.OFPActionSetField(tcp_dst=55555),
                        ofpp.OFPActionOutput(ofport_tap_meta, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=metadata_flows_process.METADATA_V4_IP,
                    tcp_dst=80,
                    ip_proto=in_proto.IPPROTO_TCP),
                priority=202,
                table_id=p_const.METADATA_EGRESS_OUTPUT),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_arp_responder_dhcp_port(self):
        dhcp_port_ip = "192.168.100.2"
        self.flows.install_arp_responder(
            ip=dhcp_port_ip,
            mac=metadata_path.METADATA_DEFAULT_MAC,
            bridge=self.int_br,
            table=p_const.TRANSIENT_TABLE)

        (dp, ofp, ofpp) = self.int_br._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.int_br.default_cookie,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(arp_op=2),
                        ofpp.NXActionRegMove(
                            dst_field='arp_tha',
                            n_bits=48,
                            src_field='arp_sha'),
                        ofpp.NXActionRegMove(
                            dst_field='arp_tpa',
                            n_bits=32,
                            src_field='arp_spa'),
                        ofpp.OFPActionSetField(
                            arp_sha=metadata_path.METADATA_DEFAULT_MAC),
                        ofpp.OFPActionSetField(arp_spa=dhcp_port_ip),
                        ofpp.NXActionRegMove(src_field='eth_src',
                                             dst_field='eth_dst',
                                             n_bits=48),
                        ofpp.OFPActionSetField(
                            eth_src=metadata_path.METADATA_DEFAULT_MAC),
                        ofpp.OFPActionOutput(ofp.OFPP_IN_PORT, 0),
                    ]),
                ],
                match=self.flows.get_arp_responder_match(
                    ofp, ofpp, ip=dhcp_port_ip),
                priority=200,
                table_id=p_const.TRANSIENT_TABLE),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.int_br.mock.mock_calls)

    def test_install_arp_responder_metadata_provider_ip(self):
        provider_ip = "100.100.100.100"
        provider_mac = "fa:16:ee:11:22:33"
        self.flows.install_arp_responder(provider_ip, provider_mac)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(arp_op=2),
                        ofpp.NXActionRegMove(
                            dst_field='arp_tha',
                            n_bits=48,
                            src_field='arp_sha'),
                        ofpp.NXActionRegMove(
                            dst_field='arp_tpa',
                            n_bits=32,
                            src_field='arp_spa'),
                        ofpp.OFPActionSetField(arp_sha=provider_mac),
                        ofpp.OFPActionSetField(arp_spa=provider_ip),
                        ofpp.NXActionRegMove(src_field='eth_src',
                                             dst_field='eth_dst',
                                             n_bits=48),
                        ofpp.OFPActionSetField(eth_src=provider_mac),
                        ofpp.OFPActionOutput(ofp.OFPP_IN_PORT, 0),
                    ]),
                ],
                match=self.flows.get_arp_responder_match(
                    ofp, ofpp, ip=provider_ip),
                priority=200,
                table_id=p_const.METADATA_IP_ARP_RESPONDER),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_arp_responder_dhcp_port(self):
        vm_ofport = 10
        dhcp_port_ip = "192.168.100.2"
        self.flows.delete_arp_responder(
            bridge=self.int_br,
            ip=dhcp_port_ip,
            table=p_const.ARP_SPOOF_TABLE,
            in_port=vm_ofport)

        (dp, ofp, ofpp) = self.int_br._get_dp()
        expected = [
            call.uninstall_flows(
                table_id=p_const.ARP_SPOOF_TABLE,
                match=self.flows.get_arp_responder_match(
                    ofp, ofpp, ip=dhcp_port_ip, in_port=vm_ofport)),
        ]
        self.assertEqual(expected, self.int_br.mock.mock_calls)

    def test_add_flow_snat_br_meta(self):
        vm_local_vlan = 1
        vm_mac = "aa:aa:aa:aa:aa:aa"
        vm_ip = "192.168.100.100"
        provider_mac = "fa:16:ee:11:22:33"
        provider_ip = "100.100.100.100"
        self.flows.add_flow_snat_br_meta(
            vm_local_vlan, vm_mac, vm_ip,
            provider_mac, provider_ip)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPopVlan(),
                        ofpp.OFPActionSetField(eth_src=provider_mac),
                        ofpp.OFPActionSetField(ipv4_src=provider_ip),
                    ]),
                    ofpp.OFPInstructionGotoTable(
                        table_id=p_const.METADATA_EGRESS_OUTPUT)
                ],
                match=ofpp.OFPMatch(
                    vlan_vid=vm_local_vlan | ofp.OFPVID_PRESENT,
                    eth_type=ether_types.ETH_TYPE_IP,
                    eth_src=vm_mac,
                    ipv4_src=vm_ip),
                priority=201,
                table_id=p_const.METADATA_EGRESS_NAT),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_add_flow_ingress_dnat_direct_to_int_br(self):
        vm_local_vlan = 1
        provider_vlan = 1000
        provider_ip_addr = "100.100.100.100"
        vm_mac = "aa:aa:aa:aa:aa:aa"
        vm_ip = "192.168.100.100"
        ofport_patch_meta_to_int = 100
        ofport_tap_meta = 200
        self.flows.add_flow_ingress_dnat_direct_to_int_br(
            vm_local_vlan, provider_vlan, provider_ip_addr,
            vm_mac, vm_ip,
            ofport_patch_meta_to_int, ofport_tap_meta)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(
                            vlan_vid=vm_local_vlan | ofp.OFPVID_PRESENT),
                        ofpp.OFPActionSetField(eth_dst=vm_mac),
                        ofpp.OFPActionSetField(
                            ipv4_src=metadata_flows_process.METADATA_V4_IP),
                        ofpp.OFPActionSetField(ipv4_dst=vm_ip),
                        ofpp.OFPActionSetField(
                            tcp_src=metadata_flows_process.METADATA_V4_PORT),
                        ofpp.OFPActionOutput(ofport_patch_meta_to_int, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    vlan_vid=provider_vlan | ofp.OFPVID_PRESENT,
                    in_port=ofport_tap_meta,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=provider_ip_addr,
                    ip_proto=in_proto.IPPROTO_TCP),
                priority=202,
                table_id=p_const.METADATA_INGRESS_DIRECT),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_add_flow_int_br_egress_direct(self):
        vm_ofport = 10
        vm_local_vlan = 1
        patch_to_br_meta = 1
        self.flows.add_flow_int_br_egress_direct(
            vm_ofport, vm_local_vlan, patch_to_br_meta)

        (dp, ofp, ofpp) = self.int_br._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.int_br.default_cookie,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPushVlan(),
                        ofpp.OFPActionSetField(
                            vlan_vid=vm_local_vlan | ofp.OFPVID_PRESENT),
                        ofpp.OFPActionOutput(patch_to_br_meta, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    in_port=vm_ofport,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=metadata_flows_process.METADATA_V4_IP),
                priority=200,
                table_id=p_const.LOCAL_SWITCHING),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.int_br.mock.mock_calls)

    def test_add_flow_int_br_ingress_output(self):
        ofport_from_br_meta = 1
        vm_local_vlan = 1
        vm_mac = "aa:aa:aa:aa:aa:aa"
        vm_ofport = 10
        self.flows.add_flow_int_br_ingress_output(
            ofport_from_br_meta, vm_local_vlan, vm_mac, vm_ofport)

        (dp, ofp, ofpp) = self.int_br._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.int_br.default_cookie,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPopVlan(),
                        ofpp.OFPActionOutput(vm_ofport, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    in_port=ofport_from_br_meta,
                    eth_type=ether_types.ETH_TYPE_IP,
                    vlan_vid=vm_local_vlan | ofp.OFPVID_PRESENT,
                    eth_dst=vm_mac,
                    ipv4_src=metadata_flows_process.METADATA_V4_IP),
                priority=200,
                table_id=p_const.LOCAL_SWITCHING),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.int_br.mock.mock_calls)

    def test_remove_port_metadata_path_nat_and_arp_flow(self):
        port_vlan = 1
        vm_mac = "aa:aa:aa:aa:aa:aa"
        vm_ip = "192.168.100.100"
        provider_vlan = 1000
        provider_ip_addr = "100.100.100.100"
        self.flows.remove_port_metadata_path_nat_and_arp_flow(
            port_vlan, vm_mac, vm_ip, provider_vlan,
            provider_ip_addr)

        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                table_id=p_const.METADATA_EGRESS_NAT,
                eth_type=ether_types.ETH_TYPE_IP,
                eth_src=vm_mac,
                ipv4_src=vm_ip,
                vlan_vid=port_vlan | ofp.OFPVID_PRESENT),
            call.uninstall_flows(
                table_id=p_const.METADATA_IP_ARP_RESPONDER,
                eth_type=ether_types.ETH_TYPE_ARP,
                arp_tpa=provider_ip_addr),
            call.uninstall_flows(
                table_id=p_const.METADATA_INGRESS_DIRECT,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=provider_ip_addr,
                vlan_vid=provider_vlan | ofp.OFPVID_PRESENT),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_port_metadata_direct_flow(self):
        vm_ofport = 10
        vm_local_vlan = 1
        vm_mac = "aa:aa:aa:aa:aa:aa"
        patch_to_br_meta = 1
        self.flows.remove_port_metadata_direct_flow(
            vm_ofport, vm_local_vlan, vm_mac,
            patch_to_br_meta)

        (dp, ofp, ofpp) = self.int_br._get_dp()
        expected = [
            call.uninstall_flows(
                table_id=p_const.LOCAL_SWITCHING,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=metadata_flows_process.METADATA_V4_IP,
                in_port=vm_ofport),
            call.uninstall_flows(
                table_id=p_const.LOCAL_SWITCHING,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=metadata_flows_process.METADATA_V4_IP,
                in_port=patch_to_br_meta,
                vlan_vid=vm_local_vlan | ofp.OFPVID_PRESENT,
                eth_dst=vm_mac),
        ]
        self.assertEqual(expected, self.int_br.mock.mock_calls)
