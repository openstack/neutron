# Copyright (c) 2023 China Unicom Cloud Data Co.,Ltd.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants as p_const
from oslo_log import log as logging

from os_ken.lib.packet import arp
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import in_proto

LOG = logging.getLogger(__name__)
METADATA_V4_IP = constants.METADATA_V4_IP
METADATA_V4_PORT = constants.METADATA_PORT


class MetadataDataPathFlows:

    def set_path_br(self, path_br):
        self.path_br = path_br

    def metadata_path_defaults(self, pvid, to_int_ofport, metadata_ofport,
                               metadata_host_info):
        for table in [p_const.METADATA_EGRESS_NAT,
                      p_const.METADATA_IP_ARP_RESPONDER,
                      p_const.METADATA_INGRESS_DIRECT]:
            self.path_br.install_drop(table_id=table)
        self.metadata_egress_direct(to_int_ofport)
        self.metadata_ingress_direct(pvid, metadata_ofport)
        self.metadata_path_classify(metadata_ofport,
                                    metadata_host_info)
        self.metadata_arp_direct(metadata_ofport)

    def metadata_egress_direct(self, in_port):
        self.path_br.install_goto(table_id=p_const.LOCAL_SWITCHING,
                                  priority=201,
                                  in_port=in_port,
                                  ipv4_dst=METADATA_V4_IP,
                                  eth_type=ether_types.ETH_TYPE_IP,
                                  dest_table_id=p_const.METADATA_EGRESS_NAT)

    def metadata_ingress_direct(self, pvid, in_port):
        (_dp, ofp, ofpp) = self.path_br._get_dp()
        match = ofpp.OFPMatch(in_port=in_port,
                              eth_type=ether_types.ETH_TYPE_IP)

        actions = [
            ofpp.OFPActionPushVlan(),
            ofpp.OFPActionSetField(vlan_vid=pvid | ofp.OFPVID_PRESENT)
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
            ofpp.OFPInstructionGotoTable(
                table_id=p_const.METADATA_INGRESS_DIRECT)
        ]
        self.path_br.install_instructions(
            table_id=p_const.LOCAL_SWITCHING,
            priority=201,
            instructions=instructions,
            match=match)

    def metadata_arp_direct(self, in_port):
        (_dp, ofp, ofpp) = self.path_br._get_dp()
        match = ofpp.OFPMatch(in_port=in_port,
                              eth_type=ether_types.ETH_TYPE_ARP)

        instructions = [
            ofpp.OFPInstructionGotoTable(
                table_id=p_const.METADATA_IP_ARP_RESPONDER)
        ]

        self.path_br.install_instructions(
            table_id=p_const.LOCAL_SWITCHING,
            priority=201,
            instructions=instructions,
            match=match)

    def metadata_path_classify(self, metadata_ofport,
                               metadata_host_info):
        agent_metadata_ip = metadata_host_info.get("provider_ip")
        agent_metadata_mac = metadata_host_info.get("mac_address")
        listen_port = metadata_host_info.get("service_protocol_port")

        (_dp, ofp, ofpp) = self.path_br._get_dp()
        match = ofpp.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=METADATA_V4_IP,
            tcp_dst=METADATA_V4_PORT,
            ip_proto=in_proto.IPPROTO_TCP)
        actions = [
            ofpp.OFPActionSetField(eth_dst=agent_metadata_mac),
            ofpp.OFPActionSetField(ipv4_dst=agent_metadata_ip),
            ofpp.OFPActionSetField(tcp_dst=listen_port),
            ofpp.OFPActionOutput(metadata_ofport, 0),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        self.path_br.install_instructions(
            table_id=p_const.METADATA_EGRESS_OUTPUT,
            priority=202,
            match=match,
            instructions=instructions)

    @staticmethod
    def get_arp_responder_match(ofp, ofpp, ip, in_port=None):
        if in_port:
            match = ofpp.OFPMatch(in_port=in_port,
                                  eth_type=ether_types.ETH_TYPE_ARP,
                                  arp_op=arp.ARP_REQUEST,
                                  arp_tpa=ip)
        else:
            match = ofpp.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                  arp_op=arp.ARP_REQUEST,
                                  arp_tpa=ip)
        return match

    def install_arp_responder(self, ip, mac, bridge=None, table=None,
                              in_port=None):
        br = bridge if bridge else self.path_br
        table_id = (table if table is not None else
                    p_const.METADATA_IP_ARP_RESPONDER)
        (_dp, ofp, ofpp) = br._get_dp()
        match = self.get_arp_responder_match(ofp, ofpp, ip, in_port)
        actions = [ofpp.OFPActionSetField(arp_op=arp.ARP_REPLY),
                   ofpp.NXActionRegMove(src_field='arp_sha',
                                        dst_field='arp_tha',
                                        n_bits=48),
                   ofpp.NXActionRegMove(src_field='arp_spa',
                                        dst_field='arp_tpa',
                                        n_bits=32),
                   ofpp.OFPActionSetField(arp_sha=mac),
                   ofpp.OFPActionSetField(arp_spa=ip),
                   ofpp.NXActionRegMove(src_field='eth_src',
                                        dst_field='eth_dst',
                                        n_bits=48),
                   ofpp.OFPActionSetField(eth_src=mac),
                   ofpp.OFPActionOutput(ofp.OFPP_IN_PORT, 0)]
        br.install_apply_actions(
            table_id=table_id,
            priority=200,
            match=match,
            actions=actions)

    def delete_arp_responder(self, ip, bridge=None, table=None,
                             in_port=None):
        br = bridge if bridge else self.path_br
        table_id = (table if table is not None else
                    p_const.METADATA_IP_ARP_RESPONDER)
        (_dp, ofp, ofpp) = br._get_dp()
        match = self.get_arp_responder_match(ofp, ofpp, ip, in_port)
        br.uninstall_flows(table_id=table_id, match=match)

    def add_flow_snat_br_meta(self, vlan, src_mac, src_ip,
                              provider_mac, provider_ip):
        (_dp, ofp, ofpp) = self.path_br._get_dp()

        match = ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT,
                              eth_type=ether_types.ETH_TYPE_IP,
                              eth_src=src_mac,
                              ipv4_src=src_ip)
        actions = [
            ofpp.OFPActionPopVlan(),
            ofpp.OFPActionSetField(eth_src=provider_mac),
            ofpp.OFPActionSetField(ipv4_src=provider_ip),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
            ofpp.OFPInstructionGotoTable(
                table_id=p_const.METADATA_EGRESS_OUTPUT)
        ]
        self.path_br.install_instructions(table_id=p_const.METADATA_EGRESS_NAT,
                                          priority=201,
                                          instructions=instructions,
                                          match=match)

    def add_flow_ingress_dnat_direct_to_int_br(
            self, vlan, provider_vlan, provider_ip,
            dst_mac, dst_ip, patch_ofport,
            tap_meta_ofport):
        (_dp, ofp, ofpp) = self.path_br._get_dp()

        match = ofpp.OFPMatch(
            vlan_vid=provider_vlan | ofp.OFPVID_PRESENT,
            in_port=tap_meta_ofport,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=provider_ip,
            ip_proto=in_proto.IPPROTO_TCP)
        actions = [
            ofpp.OFPActionSetField(vlan_vid=vlan | ofp.OFPVID_PRESENT),
            ofpp.OFPActionSetField(eth_dst=dst_mac),
            ofpp.OFPActionSetField(
                ipv4_src=METADATA_V4_IP),
            ofpp.OFPActionSetField(ipv4_dst=dst_ip),
            ofpp.OFPActionSetField(
                tcp_src=METADATA_V4_PORT),
            ofpp.OFPActionOutput(patch_ofport, 0),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        self.path_br.install_instructions(
            table_id=p_const.METADATA_INGRESS_DIRECT,
            priority=202,
            instructions=instructions,
            match=match)

    def add_flow_int_br_egress_direct(self, in_port, vlan, patch_ofport):
        (_dp, ofp, ofpp) = self.int_br._get_dp()

        match = ofpp.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=METADATA_V4_IP)

        actions = [
            ofpp.OFPActionPushVlan(),
            ofpp.OFPActionSetField(vlan_vid=vlan | ofp.OFPVID_PRESENT),
            ofpp.OFPActionOutput(patch_ofport, 0),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        self.int_br.install_instructions(table_id=p_const.LOCAL_SWITCHING,
                                         priority=200,
                                         instructions=instructions,
                                         match=match)

    def add_flow_int_br_ingress_output(self, in_port, vlan, mac, vm_ofport):
        (_dp, ofp, ofpp) = self.int_br._get_dp()

        match = ofpp.OFPMatch(in_port=in_port,
                              eth_type=ether_types.ETH_TYPE_IP,
                              vlan_vid=vlan | ofp.OFPVID_PRESENT,
                              eth_dst=mac,
                              ipv4_src=METADATA_V4_IP)
        actions = [
            ofpp.OFPActionPopVlan(),
            ofpp.OFPActionOutput(vm_ofport, 0),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)
        ]
        self.int_br.install_instructions(table_id=p_const.LOCAL_SWITCHING,
                                         priority=200,
                                         instructions=instructions,
                                         match=match)

    def remove_port_metadata_path_nat_and_arp_flow(
            self, port_vlan, port_mac, port_fixed_ip,
            provider_vlan, provider_ip_addr):
        (_dp, ofp, _ofpp) = self.path_br._get_dp()

        self.path_br.uninstall_flows(
            table_id=p_const.METADATA_EGRESS_NAT,
            eth_type=ether_types.ETH_TYPE_IP,
            eth_src=port_mac,
            ipv4_src=port_fixed_ip,
            vlan_vid=port_vlan | ofp.OFPVID_PRESENT)
        self.path_br.uninstall_flows(
            table_id=p_const.METADATA_IP_ARP_RESPONDER,
            eth_type=ether_types.ETH_TYPE_ARP,
            arp_tpa=provider_ip_addr)
        self.path_br.uninstall_flows(
            table_id=p_const.METADATA_INGRESS_DIRECT,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=provider_ip_addr,
            vlan_vid=provider_vlan | ofp.OFPVID_PRESENT)

    def remove_port_metadata_direct_flow(
            self, ofport, port_vlan, port_mac,
            ofport_int_to_snat):
        (_dp, ofp, _ofpp) = self.int_br._get_dp()

        self.int_br.uninstall_flows(
            table_id=p_const.LOCAL_SWITCHING,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=METADATA_V4_IP,
            in_port=ofport)
        self.int_br.uninstall_flows(
            table_id=p_const.LOCAL_SWITCHING,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=METADATA_V4_IP,
            in_port=ofport_int_to_snat,
            vlan_vid=port_vlan | ofp.OFPVID_PRESENT,
            eth_dst=port_mac)
