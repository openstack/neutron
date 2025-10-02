# Copyright 2011 VMware, Inc.
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

from neutron_lib import constants as lib_constants
from neutron_lib.plugins.ml2 import ovs_constants as constants
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import icmpv6
from os_ken.lib.packet import in_proto

from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import br_dvr_process
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge


class OVSTunnelBridge(ovs_bridge.OVSAgentBridge,
                      br_dvr_process.OVSDVRProcessMixin):
    """openvswitch agent tunnel bridge specific logic."""

    # Used by OVSDVRProcessMixin
    dvr_process_table_id = constants.DVR_PROCESS
    dvr_process_next_table_id = constants.PATCH_LV_TO_TUN
    of_tables = constants.TUN_BR_ALL_TABLES

    def _setup_learn_flows(self, ofpp, patch_int_ofport):
        flow_specs = [
            ofpp.NXFlowSpecMatch(src=('vlan_tci', 0),
                                 dst=('vlan_tci', 0),
                                 n_bits=12),
            ofpp.NXFlowSpecMatch(src=('eth_src', 0),
                                 dst=('eth_dst', 0),
                                 n_bits=48),
            ofpp.NXFlowSpecLoad(src=0,
                                dst=('vlan_tci', 0),
                                n_bits=16),
            ofpp.NXFlowSpecLoad(src=('tunnel_id', 0),
                                dst=('tunnel_id', 0),
                                n_bits=64),
            ofpp.NXFlowSpecOutput(src=('in_port', 0),
                                  dst='',
                                  n_bits=32),
        ]
        actions = [
            ofpp.NXActionLearn(table_id=constants.UCAST_TO_TUN,
                               cookie=self.default_cookie,
                               priority=1,
                               hard_timeout=300,
                               specs=flow_specs),
            ofpp.OFPActionOutput(patch_int_ofport, 0),
        ]

        arp_match = ofpp.OFPMatch(
            eth_type=ether_types.ETH_TYPE_ARP,
            arp_tha=lib_constants.BROADCAST_MAC
        )
        ipv6_ra_match = ofpp.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IPV6,
            ip_proto=in_proto.IPPROTO_ICMPV6,
            icmpv6_type=icmpv6.ND_ROUTER_ADVERT)  # icmp_type=134
        ipv6_na_match = ofpp.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IPV6,
            ip_proto=in_proto.IPPROTO_ICMPV6,
            icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT)  # icmp_type=136

        self.install_apply_actions(table_id=constants.LEARN_FROM_TUN,
                                   priority=2,
                                   match=arp_match,
                                   actions=actions)
        self.install_apply_actions(table_id=constants.LEARN_FROM_TUN,
                                   priority=2,
                                   match=ipv6_ra_match,
                                   actions=actions)
        self.install_apply_actions(table_id=constants.LEARN_FROM_TUN,
                                   priority=2,
                                   match=ipv6_na_match,
                                   actions=actions)
        self.install_apply_actions(table_id=constants.LEARN_FROM_TUN,
                                   priority=1,
                                   actions=actions)

    def setup_default_table(
            self, patch_int_ofport, arp_responder_enabled, dvr_enabled):
        (dp, ofp, ofpp) = self._get_dp()

        if not dvr_enabled:
            # Table 0 (default) will sort incoming traffic depending on in_port
            # This table is needed only for non-dvr environment because
            # OVSDVRProcessMixin overwrites this flow in its
            # install_dvr_process() method.
            self.install_goto(dest_table_id=constants.PATCH_LV_TO_TUN,
                              priority=1,
                              in_port=patch_int_ofport)

        self.install_drop()  # default drop

        if arp_responder_enabled:
            # ARP broadcast-ed request go to the local ARP_RESPONDER table to
            # be locally resolved
            # REVISIT(yamamoto): add arp_op=arp.ARP_REQUEST matcher?
            self.install_goto(dest_table_id=constants.ARP_RESPONDER,
                              table_id=constants.PATCH_LV_TO_TUN,
                              priority=1,
                              eth_dst="ff:ff:ff:ff:ff:ff",
                              eth_type=ether_types.ETH_TYPE_ARP)

        # PATCH_LV_TO_TUN table will handle packets coming from patch_int
        # unicasts go to table UCAST_TO_TUN where remote addresses are learnt
        self.install_goto(dest_table_id=constants.UCAST_TO_TUN,
                          table_id=constants.PATCH_LV_TO_TUN,
                          eth_dst=('00:00:00:00:00:00',
                                   '01:00:00:00:00:00'))

        # Broadcasts/multicasts go to table FLOOD_TO_TUN that handles flooding
        self.install_goto(dest_table_id=constants.FLOOD_TO_TUN,
                          table_id=constants.PATCH_LV_TO_TUN,
                          eth_dst=('01:00:00:00:00:00',
                                   '01:00:00:00:00:00'))

        # Tables [tunnel_type]_TUN_TO_LV will set lvid depending on tun_id
        # for each tunnel type, and resubmit to table LEARN_FROM_TUN where
        # remote mac addresses will be learnt
        for tunnel_type in constants.TUNNEL_NETWORK_TYPES:
            self.install_drop(table_id=constants.TUN_TABLE[tunnel_type])

        # LEARN_FROM_TUN table will have a single flow using a learn action to
        # dynamically set-up flows in UCAST_TO_TUN corresponding to remote mac
        # addresses (assumes that lvid has already been set by a previous flow)
        # Once remote mac addresses are learnt, output packet to patch_int
        self._setup_learn_flows(ofpp, patch_int_ofport)

        # Egress unicast will be handled in table UCAST_TO_TUN, where remote
        # mac addresses will be learned. For now, just add a default flow that
        # will resubmit unknown unicasts to table FLOOD_TO_TUN to treat them
        # as broadcasts/multicasts
        self.install_goto(dest_table_id=constants.FLOOD_TO_TUN,
                          table_id=constants.UCAST_TO_TUN)

        if arp_responder_enabled:
            # If none of the ARP entries correspond to the requested IP, the
            # broadcast-ed packet is resubmitted to the flooding table
            self.install_goto(dest_table_id=constants.FLOOD_TO_TUN,
                              table_id=constants.ARP_RESPONDER)

        # FLOOD_TO_TUN will handle flooding in tunnels based on lvid,
        # for now, add a default drop action
        self.install_drop(table_id=constants.FLOOD_TO_TUN)

    @staticmethod
    def _local_vlan_match(_ofp, ofpp, tun_id):
        return ofpp.OFPMatch(tunnel_id=tun_id)

    def provision_local_vlan(self, network_type, lvid, segmentation_id,
                             distributed=False):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._local_vlan_match(ofp, ofpp, segmentation_id)
        table_id = constants.TUN_TABLE[network_type]
        if distributed:
            dest_table_id = constants.DVR_NOT_LEARN
        else:
            dest_table_id = constants.LEARN_FROM_TUN
        actions = [
            ofpp.OFPActionPushVlan(),
            ofpp.OFPActionSetField(vlan_vid=lvid | ofp.OFPVID_PRESENT),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
            ofpp.OFPInstructionGotoTable(table_id=dest_table_id)]
        self.install_instructions(table_id=table_id,
                                  priority=1,
                                  match=match,
                                  instructions=instructions)

    def reclaim_local_vlan(self, network_type, segmentation_id):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._local_vlan_match(ofp, ofpp, segmentation_id)
        table_id = constants.TUN_TABLE[network_type]
        self.uninstall_flows(table_id=table_id, match=match)

    @staticmethod
    def _flood_to_tun_match(ofp, ofpp, vlan):
        return ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT)

    def install_flood_to_tun(self, vlan, tun_id, ports):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._flood_to_tun_match(ofp, ofpp, vlan)
        actions = [ofpp.OFPActionPopVlan(),
                   ofpp.OFPActionSetField(tunnel_id=tun_id)]
        for port in ports:
            actions.append(ofpp.OFPActionOutput(port, 0))
        self.install_apply_actions(table_id=constants.FLOOD_TO_TUN,
                                   priority=1,
                                   match=match,
                                   actions=actions)

    def delete_flood_to_tun(self, vlan):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._flood_to_tun_match(ofp, ofpp, vlan)
        self.uninstall_flows(table_id=constants.FLOOD_TO_TUN, match=match)

    @staticmethod
    def _unicast_to_tun_match(ofp, ofpp, vlan, mac):
        return ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT, eth_dst=mac)

    def install_unicast_to_tun(self, vlan, tun_id, port, mac):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._unicast_to_tun_match(ofp, ofpp, vlan, mac)
        actions = [ofpp.OFPActionPopVlan(),
                   ofpp.OFPActionSetField(tunnel_id=tun_id),
                   ofpp.OFPActionOutput(port, 0)]
        self.install_apply_actions(table_id=constants.UCAST_TO_TUN,
                                   priority=2,
                                   match=match,
                                   actions=actions)

    def delete_unicast_to_tun(self, vlan, mac):
        (_dp, ofp, ofpp) = self._get_dp()
        if mac is None:
            match = ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT)
        else:
            match = self._unicast_to_tun_match(ofp, ofpp, vlan, mac)
        self.uninstall_flows(table_id=constants.UCAST_TO_TUN, match=match)

    @staticmethod
    def _arp_responder_match(ofp, ofpp, vlan, ip):
        # REVISIT(yamamoto): add arp_op=arp.ARP_REQUEST matcher?
        return ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT,
                             eth_type=ether_types.ETH_TYPE_ARP,
                             arp_tpa=ip)

    def delete_arp_responder(self, vlan, ip):
        (_dp, ofp, ofpp) = self._get_dp()
        if ip is None:
            # REVISIT(yamamoto): add arp_op=arp.ARP_REQUEST matcher?
            match = ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT,
                                  eth_type=ether_types.ETH_TYPE_ARP)
        else:
            match = self._arp_responder_match(ofp, ofpp, vlan, ip)
        self.uninstall_flows(table_id=constants.ARP_RESPONDER,
                             match=match)

    def setup_tunnel_port(self, network_type, port):
        self.install_goto(dest_table_id=constants.TUN_TABLE[network_type],
                          priority=1,
                          in_port=port)

    def cleanup_tunnel_port(self, port):
        self.uninstall_flows(in_port=port)

    def add_dvr_mac_tun(self, mac, port):
        self.install_output(table_id=constants.DVR_NOT_LEARN,
                            priority=1,
                            eth_src=mac,
                            port=port)

    def remove_dvr_mac_tun(self, mac):
        # REVISIT(yamamoto): match in_port as well?
        self.uninstall_flows(table_id=constants.DVR_NOT_LEARN,
                             eth_src=mac)
