# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
# Copyright (c) 2021-2022 Chinaunicom
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

"""
* references
** OVS agent https://wiki.openstack.org/wiki/Ovs-flow-logic
"""

import netaddr

from neutron_lib import constants as lib_consts
from neutron_lib.plugins.ml2 import ovs_constants as constants
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import icmpv6
from os_ken.lib.packet import in_proto
from oslo_log import log as logging

from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import br_dvr_process
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge


LOG = logging.getLogger(__name__)

# TODO(liuyulong): move to neutron-lib.
IPV4_NETWORK_BROADCAST = "255.255.255.255"
# All_DHCP_Relay_Agents_and_Servers
# [RFC8415] https://datatracker.ietf.org/doc/html/rfc8415
IPV6_All_DHCP_RELAY_AGENYS_AND_SERVERS = "ff02::1:2"


class OVSIntegrationBridge(ovs_bridge.OVSAgentBridge,
                           br_dvr_process.OVSDVRInterfaceMixin):
    """openvswitch agent br-int specific logic."""

    of_tables = constants.INT_BR_ALL_TABLES

    def setup_default_table(self, enable_openflow_dhcp=False,
                            enable_dhcpv6=False):
        (_dp, ofp, ofpp) = self._get_dp()
        self.setup_canary_table()
        self.install_goto(dest_table_id=constants.PACKET_RATE_LIMIT)
        self.install_goto(dest_table_id=constants.TRANSIENT_TABLE,
                          table_id=constants.PACKET_RATE_LIMIT)
        self.install_normal(table_id=constants.TRANSIENT_TABLE, priority=3)
        self.init_dhcp(enable_openflow_dhcp=enable_openflow_dhcp,
                       enable_dhcpv6=enable_dhcpv6)
        self.install_drop(table_id=constants.ARP_SPOOF_TABLE)
        self.install_drop(
            table_id=constants.LOCAL_SWITCHING,
            priority=constants.OPENFLOW_MAX_PRIORITY,
            vlan_vid=ofp.OFPVID_PRESENT | constants.DEAD_VLAN_TAG,
        )
        # When openflow firewall is not enabled, we use this table to
        # deal with all egress flow.
        self.install_normal(table_id=constants.TRANSIENT_EGRESS_TABLE,
                            priority=3)

        # Local IP defaults
        self.install_goto(dest_table_id=constants.PACKET_RATE_LIMIT,
                          table_id=constants.LOCAL_EGRESS_TABLE)
        self.install_goto(dest_table_id=constants.PACKET_RATE_LIMIT,
                          table_id=constants.LOCAL_IP_TABLE)

    def init_dhcp(self, enable_openflow_dhcp=False, enable_dhcpv6=False):
        if not enable_openflow_dhcp:
            return
        # DHCP IPv4
        self.install_goto(dest_table_id=constants.DHCP_IPV4_TABLE,
                          table_id=constants.TRANSIENT_TABLE,
                          priority=101,
                          eth_type=ether_types.ETH_TYPE_IP,
                          ip_proto=in_proto.IPPROTO_UDP,
                          ipv4_dst=IPV4_NETWORK_BROADCAST,
                          udp_src=lib_consts.DHCP_CLIENT_PORT,
                          udp_dst=lib_consts.DHCP_RESPONSE_PORT)
        self.install_drop(table_id=constants.DHCP_IPV4_TABLE)

        if not enable_dhcpv6:
            return
        # DHCP IPv6
        self.install_goto(dest_table_id=constants.DHCP_IPV6_TABLE,
                          table_id=constants.TRANSIENT_TABLE,
                          priority=101,
                          eth_type=ether_types.ETH_TYPE_IPV6,
                          ip_proto=in_proto.IPPROTO_UDP,
                          ipv6_dst=IPV6_All_DHCP_RELAY_AGENYS_AND_SERVERS,
                          udp_src=lib_consts.DHCPV6_CLIENT_PORT,
                          udp_dst=lib_consts.DHCPV6_RESPONSE_PORT)
        self.install_drop(table_id=constants.DHCP_IPV6_TABLE)

    def add_dhcp_ipv4_flow(self, port_id, ofport, port_mac):
        (_dp, ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                              ip_proto=in_proto.IPPROTO_UDP,
                              in_port=ofport,
                              eth_src=port_mac,
                              udp_src=68,
                              udp_dst=67)
        actions = [
            ofpp.OFPActionOutput(ofp.OFPP_CONTROLLER, 0),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        self.install_instructions(table_id=constants.DHCP_IPV4_TABLE,
                                  priority=100,
                                  instructions=instructions,
                                  match=match)

    def add_dhcp_ipv6_flow(self, port_id, ofport, port_mac):
        (_dp, ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                              ip_proto=in_proto.IPPROTO_UDP,
                              in_port=ofport,
                              eth_src=port_mac,
                              udp_src=546,
                              udp_dst=547)
        actions = [
            ofpp.OFPActionOutput(ofp.OFPP_CONTROLLER, 0),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        self.install_instructions(table_id=constants.DHCP_IPV6_TABLE,
                                  priority=100,
                                  instructions=instructions,
                                  match=match)

    def del_dhcp_flow(self, ofport, port_mac):
        self.uninstall_flows(table_id=constants.DHCP_IPV4_TABLE,
                             eth_type=ether_types.ETH_TYPE_IP,
                             ip_proto=in_proto.IPPROTO_UDP,
                             in_port=ofport,
                             eth_src=port_mac,
                             udp_src=68,
                             udp_dst=67)
        self.uninstall_flows(table_id=constants.DHCP_IPV6_TABLE,
                             eth_type=ether_types.ETH_TYPE_IPV6,
                             ip_proto=in_proto.IPPROTO_UDP,
                             in_port=ofport,
                             eth_src=port_mac,
                             udp_src=546,
                             udp_dst=547)

    def setup_canary_table(self):
        self.install_drop(constants.CANARY_TABLE)

    def check_canary_table(self):
        try:
            flows = self.dump_flows(constants.CANARY_TABLE)
        except RuntimeError:
            LOG.exception("Failed to communicate with the switch")
            return constants.OVS_DEAD
        return constants.OVS_NORMAL if flows else constants.OVS_RESTARTED

    @staticmethod
    def _local_vlan_match(_ofp, ofpp, port, vlan_vid):
        return ofpp.OFPMatch(in_port=port, vlan_vid=vlan_vid)

    def provision_local_vlan(self, port, lvid, segmentation_id):
        (_dp, ofp, ofpp) = self._get_dp()
        if segmentation_id is None:
            vlan_vid = ofp.OFPVID_NONE
            actions = [ofpp.OFPActionPushVlan()]
        else:
            vlan_vid = segmentation_id | ofp.OFPVID_PRESENT
            actions = []
        match = self._local_vlan_match(ofp, ofpp, port, vlan_vid)
        actions += [
            ofpp.OFPActionSetField(vlan_vid=lvid | ofp.OFPVID_PRESENT),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
            ofpp.OFPInstructionGotoTable(table_id=constants.PACKET_RATE_LIMIT),
        ]
        self.install_instructions(
            instructions=instructions,
            priority=3,
            match=match,
        )

    def reclaim_local_vlan(self, port, segmentation_id):
        (_dp, ofp, ofpp) = self._get_dp()
        if segmentation_id is None:
            vlan_vid = ofp.OFPVID_NONE
        else:
            vlan_vid = segmentation_id | ofp.OFPVID_PRESENT
        match = self._local_vlan_match(ofp, ofpp, port, vlan_vid)
        self.uninstall_flows(match=match)

    @staticmethod
    def _arp_dvr_dst_mac_match(ofp, ofpp, vlan, dvr_mac):
        # If eth_dst is equal to the dvr mac of this host, then
        # flag it as matched.
        if not vlan:
            return ofpp.OFPMatch(vlan_vid=ofp.OFPVID_NONE, eth_dst=dvr_mac)
        return ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT,
                             eth_dst=dvr_mac)

    @staticmethod
    def _dvr_dst_mac_table_id(network_type):
        if network_type in constants.DVR_PHYSICAL_NETWORK_TYPES:
            return constants.ARP_DVR_MAC_TO_DST_MAC_PHYSICAL
        else:
            return constants.ARP_DVR_MAC_TO_DST_MAC

    def install_dvr_dst_mac_for_arp(self, network_type,
                                    vlan_tag, gateway_mac, dvr_mac, rtr_port):
        table_id = self._dvr_dst_mac_table_id(network_type)
        # Match the destination MAC with the DVR MAC
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._arp_dvr_dst_mac_match(ofp, ofpp, vlan_tag, dvr_mac)
        # Incoming packet will come with destination MAC of DVR host MAC from
        # the ARP Responder. The Source MAC in this case will have the source
        # MAC of the port MAC that responded from the ARP responder.
        # So just remove the DVR host MAC from the 'eth_dst' and replace it
        # with the gateway-mac. The packet should end up in the right the table
        # for the packet to reach the router interface.
        actions = [
            ofpp.OFPActionSetField(eth_dst=gateway_mac),
            ofpp.OFPActionPopVlan(),
            ofpp.OFPActionOutput(rtr_port, 0)
        ]
        self.install_apply_actions(table_id=table_id,
                                   priority=5,
                                   match=match,
                                   actions=actions)

    @staticmethod
    def _dvr_to_src_mac_match(ofp, ofpp, vlan_tag, dst_mac):
        if not vlan_tag:
            # When the network is flat type, the vlan_tag will be None.
            return ofpp.OFPMatch(vlan_vid=ofp.OFPVID_NONE, eth_dst=dst_mac)
        return ofpp.OFPMatch(vlan_vid=vlan_tag | ofp.OFPVID_PRESENT,
                             eth_dst=dst_mac)

    @staticmethod
    def _dvr_to_src_mac_table_id(network_type):
        if network_type in constants.DVR_PHYSICAL_NETWORK_TYPES:
            return constants.DVR_TO_SRC_MAC_PHYSICAL
        else:
            return constants.DVR_TO_SRC_MAC

    def install_dvr_to_src_mac(self, network_type,
                               vlan_tag, gateway_mac, dst_mac, dst_port):
        table_id = self._dvr_to_src_mac_table_id(network_type)
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_to_src_mac_match(ofp, ofpp,
                                           vlan_tag=vlan_tag, dst_mac=dst_mac)
        actions = [
            ofpp.OFPActionSetField(eth_src=gateway_mac),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
            ofpp.OFPInstructionGotoTable(table_id=constants.PACKET_RATE_LIMIT),
        ]
        self.install_instructions(table_id=table_id,
                                  priority=20,
                                  match=match,
                                  instructions=instructions)
        actions = []
        if vlan_tag:
            actions.append(ofpp.OFPActionPopVlan())
        actions.append(ofpp.OFPActionOutput(dst_port, 0))
        self.install_apply_actions(table_id=constants.TRANSIENT_TABLE,
                                   priority=20,
                                   match=match,
                                   actions=actions)

    def delete_dvr_to_src_mac(self, network_type, vlan_tag, dst_mac):
        table_id = self._dvr_to_src_mac_table_id(network_type)
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_to_src_mac_match(ofp, ofpp,
                                           vlan_tag=vlan_tag, dst_mac=dst_mac)
        for table in (table_id, constants.TRANSIENT_TABLE):
            self.uninstall_flows(
                strict=True, priority=20, table_id=table, match=match)

    def add_dvr_mac_physical(self, mac, port):
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=4,
                          in_port=port,
                          eth_src=mac,
                          dest_table_id=constants.DVR_TO_SRC_MAC_PHYSICAL)

    def remove_dvr_mac_vlan(self, mac):
        # REVISIT(yamamoto): match in_port as well?
        self.uninstall_flows(table_id=constants.LOCAL_SWITCHING,
                             eth_src=mac)

    def add_dvr_mac_tun(self, mac, port):
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=2,
                          in_port=port,
                          eth_src=mac,
                          dest_table_id=constants.DVR_TO_SRC_MAC)

    def remove_dvr_mac_tun(self, mac, port):
        self.uninstall_flows(table_id=constants.LOCAL_SWITCHING,
                             in_port=port, eth_src=mac)

    def delete_dvr_dst_mac_for_arp(self, network_type,
                                   vlan_tag, gateway_mac, dvr_mac, rtr_port):
        table_id = self._dvr_to_src_mac_table_id(network_type)
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._arp_dvr_dst_mac_match(ofp, ofpp, vlan_tag, dvr_mac)
        self.uninstall_flows(
            strict=True, priority=5, table_id=table_id, match=match)

    def add_dvr_gateway_mac_arp_vlan(self, mac, port):
        self.install_goto(
            table_id=constants.LOCAL_SWITCHING,
            priority=5,
            in_port=port,
            eth_dst=mac,
            dest_table_id=constants.ARP_DVR_MAC_TO_DST_MAC_PHYSICAL)

    def remove_dvr_gateway_mac_arp_vlan(self, mac, port):
        self.uninstall_flows(table_id=constants.LOCAL_SWITCHING,
                             eth_dst=mac)

    def add_dvr_gateway_mac_arp_tun(self, mac, port):
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=5,
                          in_port=port,
                          eth_dst=mac,
                          dest_table_id=constants.ARP_DVR_MAC_TO_DST_MAC)

    def remove_dvr_gateway_mac_arp_tun(self, mac, port):
        self.uninstall_flows(table_id=constants.LOCAL_SWITCHING,
                             eth_dst=mac)

    @staticmethod
    def _arp_reply_match(ofp, ofpp, port):
        return ofpp.OFPMatch(in_port=port,
                             eth_type=ether_types.ETH_TYPE_ARP)

    @staticmethod
    def _icmpv6_reply_match(ofp, ofpp, port):
        return ofpp.OFPMatch(in_port=port,
                             eth_type=ether_types.ETH_TYPE_IPV6,
                             ip_proto=in_proto.IPPROTO_ICMPV6,
                             icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT)

    def install_icmpv6_na_spoofing_protection(self, port, ip_addresses):
        # Allow neighbor advertisements as long as they match addresses
        # that actually belong to the port.
        for ip in ip_addresses:
            masked_ip = self._cidr_to_os_ken(ip)
            self.install_goto(
                table_id=constants.ARP_SPOOF_TABLE, priority=2,
                eth_type=ether_types.ETH_TYPE_IPV6,
                ip_proto=in_proto.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT,
                ipv6_nd_target=masked_ip, in_port=port,
                dest_table_id=constants.PACKET_RATE_LIMIT)

        # Now that the rules are ready, direct icmpv6 neighbor advertisement
        # traffic from the port into the anti-spoof table.
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._icmpv6_reply_match(ofp, ofpp, port=port)
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=10,
                          match=match,
                          dest_table_id=constants.ARP_SPOOF_TABLE)

    def set_allowed_macs_for_port(self, port, mac_addresses=None,
                                  allow_all=False):
        if allow_all:
            self.uninstall_flows(table_id=constants.LOCAL_SWITCHING,
                                 in_port=port)
            self.uninstall_flows(table_id=constants.MAC_SPOOF_TABLE,
                                 in_port=port)
            return
        mac_addresses = mac_addresses or []
        for address in mac_addresses:
            self.install_goto(
                table_id=constants.MAC_SPOOF_TABLE, priority=2,
                eth_src=address, in_port=port,
                dest_table_id=constants.LOCAL_EGRESS_TABLE)
        # normalize so we can see if macs are the same
        mac_addresses = {netaddr.EUI(mac) for mac in mac_addresses}
        flows = self.dump_flows(constants.MAC_SPOOF_TABLE)
        for flow in flows:
            matches = dict(flow.match.items())
            if matches.get('in_port') != port:
                continue
            if not matches.get('eth_src'):
                continue
            flow_mac = matches['eth_src']
            if netaddr.EUI(flow_mac) not in mac_addresses:
                self.uninstall_flows(table_id=constants.MAC_SPOOF_TABLE,
                                     in_port=port, eth_src=flow_mac)
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=9, in_port=port,
                          dest_table_id=constants.MAC_SPOOF_TABLE)

    def install_arp_spoofing_protection(self, port, ip_addresses):
        # allow ARP replies as long as they match addresses that actually
        # belong to the port.
        for ip in ip_addresses:
            masked_ip = self._cidr_to_os_ken(ip)
            self.install_goto(table_id=constants.ARP_SPOOF_TABLE,
                              priority=2,
                              eth_type=ether_types.ETH_TYPE_ARP,
                              arp_spa=masked_ip,
                              in_port=port,
                              dest_table_id=constants.MAC_SPOOF_TABLE)

        # Now that the rules are ready, direct ARP traffic from the port into
        # the anti-spoof table.
        # This strategy fails gracefully because OVS versions that can't match
        # on ARP headers will just process traffic normally.
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._arp_reply_match(ofp, ofpp, port=port)
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=10,
                          match=match,
                          dest_table_id=constants.ARP_SPOOF_TABLE)

    def list_meter_features(self):
        (dp, _ofp, ofpp) = self._get_dp()
        req = ofpp.OFPMeterFeaturesStatsRequest(dp, 0)

        rep = self._send_msg(req, reply_cls=ofpp.OFPMeterFeaturesStatsReply)

        features = []
        for stat in rep.body:
            features.append({"max_meter": stat.max_meter,
                             "band_types": stat.band_types,
                             "capabilities": stat.capabilities,
                             "max_bands": stat.max_bands,
                             "max_color": stat.max_color})
        return features

    def create_meter(self, meter_id, rate, burst=0):
        (dp, ofp, ofpp) = self._get_dp()

        bands = [
            ofpp.OFPMeterBandDrop(rate=rate, burst_size=burst)]
        req = ofpp.OFPMeterMod(datapath=dp, command=ofp.OFPMC_ADD,
                               flags=ofp.OFPMF_PKTPS, meter_id=meter_id,
                               bands=bands)
        self._send_msg(req)

    def delete_meter(self, meter_id):
        (dp, ofp, ofpp) = self._get_dp()

        req = ofpp.OFPMeterMod(datapath=dp, command=ofp.OFPMC_DELETE,
                               flags=ofp.OFPMF_PKTPS, meter_id=meter_id)
        self._send_msg(req)

    def update_meter(self, meter_id, rate, burst=0):
        (dp, ofp, ofpp) = self._get_dp()

        bands = [
            ofpp.OFPMeterBandDrop(rate=rate, burst_size=burst)]
        req = ofpp.OFPMeterMod(datapath=dp, command=ofp.OFPMC_MODIFY,
                               flags=ofp.OFPMF_PKTPS, meter_id=meter_id,
                               bands=bands)
        self._send_msg(req)

    def apply_meter_to_port(self, meter_id, direction, mac,
                            in_port=None, local_vlan=None):
        """Add meter flows to port.

        Ingress: match dst MAC and local_vlan ID
        Egress: match src MAC and OF in_port
        """
        (_dp, ofp, ofpp) = self._get_dp()

        if direction == lib_consts.EGRESS_DIRECTION and in_port:
            match = ofpp.OFPMatch(in_port=in_port, eth_src=mac)
        elif direction == lib_consts.INGRESS_DIRECTION and local_vlan:
            vlan_vid = local_vlan | ofp.OFPVID_PRESENT
            match = ofpp.OFPMatch(vlan_vid=vlan_vid, eth_dst=mac)
        else:
            LOG.warning("Invalid inputs to add meter flows to port.")
            return

        instructions = [
            ofpp.OFPInstructionMeter(meter_id, type_=ofp.OFPIT_METER),
            ofpp.OFPInstructionGotoTable(table_id=constants.TRANSIENT_TABLE)]

        self.install_instructions(table_id=constants.PACKET_RATE_LIMIT,
                                  priority=100,
                                  instructions=instructions,
                                  match=match)

    def remove_meter_from_port(self, direction, mac,
                               in_port=None, local_vlan=None):
        """Remove meter flows from port.

        Ingress: match dst MAC and local_vlan ID
        Egress: match src MAC and OF in_port
        """
        (_dp, ofp, ofpp) = self._get_dp()

        if direction == lib_consts.EGRESS_DIRECTION and in_port:
            match = ofpp.OFPMatch(in_port=in_port, eth_src=mac)
        elif direction == lib_consts.INGRESS_DIRECTION and local_vlan:
            vlan_vid = local_vlan | ofp.OFPVID_PRESENT
            match = ofpp.OFPMatch(vlan_vid=vlan_vid, eth_dst=mac)
        else:
            LOG.warning("Invalid inputs to remove meter flows from port.")
            return

        self.uninstall_flows(table_id=constants.PACKET_RATE_LIMIT,
                             match=match)

    def delete_arp_spoofing_protection(self, port):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._arp_reply_match(ofp, ofpp, port=port)
        self.uninstall_flows(table_id=constants.LOCAL_SWITCHING,
                             match=match)
        match = self._icmpv6_reply_match(ofp, ofpp, port=port)
        self.uninstall_flows(table_id=constants.LOCAL_SWITCHING,
                             match=match)
        self.delete_arp_spoofing_allow_rules(port)

    def delete_arp_spoofing_allow_rules(self, port):
        self.uninstall_flows(table_id=constants.ARP_SPOOF_TABLE,
                             in_port=port)

    def install_dscp_marking_rule(self, port, dscp_mark):
        # reg2 is a metadata field that does not alter packets.
        # By loading a value into this field and checking if the value is
        # altered it allows the packet to be resubmitted and go through
        # the flow table again to be identified by other flows.
        (dp, ofp, ofpp) = self._get_dp()
        actions = [ofpp.OFPActionSetField(reg2=1),
                   ofpp.OFPActionSetField(ip_dscp=dscp_mark),
                   ofpp.NXActionResubmit(in_port=port)]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        self.install_instructions(instructions, table_id=0,
                                  priority=65535, in_port=port, reg2=0,
                                  eth_type=0x0800)
        self.install_instructions(instructions, table_id=0,
                                  priority=65535, in_port=port, reg2=0,
                                  eth_type=0x86DD)

    def setup_local_egress_flows(self, in_port, vlan):
        if in_port == constants.OFPORT_INVALID:
            LOG.warning("Invalid ofport: %s, vlan: %s - "
                        "skipping setup_local_egress_flows", in_port, vlan)
            return

        # Setting priority to 8 to give advantage to ARP/MAC spoofing rules
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=8,
                          in_port=in_port,
                          dest_table_id=constants.LOCAL_EGRESS_TABLE)
        (dp, ofp, ofpp) = self._get_dp()
        actions = [ofpp.OFPActionSetField(reg6=vlan),
                   ofpp.NXActionResubmitTable(
                       in_port=in_port, table_id=constants.LOCAL_IP_TABLE)]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        self.install_instructions(instructions,
                                  table_id=constants.LOCAL_EGRESS_TABLE,
                                  priority=10, in_port=in_port)

    @staticmethod
    def _arp_responder_match(ofp, ofpp, vlan, ip):
        return ofpp.OFPMatch(reg6=vlan,
                             eth_type=ether_types.ETH_TYPE_ARP,
                             arp_tpa=ip)

    def _garp_blocker_match(self, vlan, ip):
        (dp, ofp, ofpp) = self._get_dp()
        return ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT,
                             eth_type=ether_types.ETH_TYPE_ARP,
                             arp_spa=ip)

    def install_garp_blocker(self, vlan, ip,
                             table_id=constants.LOCAL_SWITCHING):
        match = self._garp_blocker_match(vlan, ip)
        self.install_drop(table_id=table_id,
                          priority=10,
                          match=match)

    def delete_garp_blocker(self, vlan, ip,
                            table_id=constants.LOCAL_SWITCHING):
        match = self._garp_blocker_match(vlan, ip)
        self.uninstall_flows(table_id=table_id,
                             priority=10,
                             match=match)

    def _garp_blocker_exception_match(self, vlan, ip, except_ip):
        (dp, ofp, ofpp) = self._get_dp()
        return ofpp.OFPMatch(vlan_vid=vlan | ofp.OFPVID_PRESENT,
                             eth_type=ether_types.ETH_TYPE_ARP,
                             arp_spa=ip,
                             arp_tpa=except_ip)

    def install_garp_blocker_exception(self, vlan, ip, except_ip,
                                       table_id=constants.LOCAL_SWITCHING):
        match = self._garp_blocker_exception_match(vlan, ip, except_ip)
        self.install_goto(dest_table_id=constants.PACKET_RATE_LIMIT,
                          table_id=table_id,
                          priority=11,
                          match=match)

    def delete_garp_blocker_exception(self, vlan, ip, except_ip,
                                      table_id=constants.LOCAL_SWITCHING):
        match = self._garp_blocker_exception_match(vlan, ip, except_ip)
        self.uninstall_flows(table_id=table_id,
                             priority=11,
                             match=match)
