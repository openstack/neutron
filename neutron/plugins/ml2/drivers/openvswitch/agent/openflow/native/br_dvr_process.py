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

from ryu.lib.packet import ether_types
from ryu.lib.packet import icmpv6
from ryu.lib.packet import in_proto


class OVSDVRProcessMixin(object):
    """Common logic for br-tun and br-phys' DVR_PROCESS tables.

    Inheriters should provide self.dvr_process_table_id and
    self.dvr_process_next_table_id.
    """

    @staticmethod
    def _dvr_process_ipv4_match(ofp, ofpp, vlan_tag, gateway_ip):
        return ofpp.OFPMatch(vlan_vid=vlan_tag | ofp.OFPVID_PRESENT,
                             eth_type=ether_types.ETH_TYPE_ARP,
                             arp_tpa=gateway_ip)

    def install_dvr_process_ipv4(self, vlan_tag, gateway_ip):
        # block ARP
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_process_ipv4_match(ofp, ofpp,
            vlan_tag=vlan_tag, gateway_ip=gateway_ip)
        self.install_drop(table_id=self.dvr_process_table_id,
                          priority=3,
                          match=match)

    def delete_dvr_process_ipv4(self, vlan_tag, gateway_ip):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_process_ipv4_match(ofp, ofpp,
            vlan_tag=vlan_tag, gateway_ip=gateway_ip)
        self.uninstall_flows(table_id=self.dvr_process_table_id,
                             match=match)

    @staticmethod
    def _dvr_process_ipv6_match(ofp, ofpp, vlan_tag, gateway_mac):
        return ofpp.OFPMatch(vlan_vid=vlan_tag | ofp.OFPVID_PRESENT,
                             eth_type=ether_types.ETH_TYPE_IPV6,
                             ip_proto=in_proto.IPPROTO_ICMPV6,
                             icmpv6_type=icmpv6.ND_ROUTER_ADVERT,
                             eth_src=gateway_mac)

    def install_dvr_process_ipv6(self, vlan_tag, gateway_mac):
        # block RA
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_process_ipv6_match(ofp, ofpp,
            vlan_tag=vlan_tag, gateway_mac=gateway_mac)
        self.install_drop(table_id=self.dvr_process_table_id, priority=3,
                          match=match)

    def delete_dvr_process_ipv6(self, vlan_tag, gateway_mac):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_process_ipv6_match(ofp, ofpp,
            vlan_tag=vlan_tag, gateway_mac=gateway_mac)
        self.uninstall_flows(table_id=self.dvr_process_table_id,
                             match=match)

    @staticmethod
    def _dvr_process_in_match(ofp, ofpp, vlan_tag, vif_mac):
        return ofpp.OFPMatch(vlan_vid=vlan_tag | ofp.OFPVID_PRESENT,
                             eth_dst=vif_mac)

    @staticmethod
    def _dvr_process_out_match(ofp, ofpp, vlan_tag, vif_mac):
        return ofpp.OFPMatch(vlan_vid=vlan_tag | ofp.OFPVID_PRESENT,
                             eth_src=vif_mac)

    def install_dvr_process(self, vlan_tag, vif_mac, dvr_mac_address):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_process_in_match(ofp, ofpp,
                                           vlan_tag=vlan_tag, vif_mac=vif_mac)
        table_id = self.dvr_process_table_id
        self.install_drop(table_id=table_id,
                          priority=2,
                          match=match)
        match = self._dvr_process_out_match(ofp, ofpp,
                                            vlan_tag=vlan_tag, vif_mac=vif_mac)
        actions = [
            ofpp.OFPActionSetField(eth_src=dvr_mac_address),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
            ofpp.OFPInstructionGotoTable(
                table_id=self.dvr_process_next_table_id),
        ]
        self.install_instructions(table_id=table_id,
                                  priority=1,
                                  match=match,
                                  instructions=instructions)

    def delete_dvr_process(self, vlan_tag, vif_mac):
        (_dp, ofp, ofpp) = self._get_dp()
        table_id = self.dvr_process_table_id
        match = self._dvr_process_in_match(ofp, ofpp,
                                           vlan_tag=vlan_tag, vif_mac=vif_mac)
        self.uninstall_flows(table_id=table_id, match=match)
        match = self._dvr_process_out_match(ofp, ofpp,
                                            vlan_tag=vlan_tag, vif_mac=vif_mac)
        self.uninstall_flows(table_id=table_id, match=match)
