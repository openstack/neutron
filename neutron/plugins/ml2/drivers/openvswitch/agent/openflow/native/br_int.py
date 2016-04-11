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

"""
* references
** OVS agent https://wiki.openstack.org/wiki/Ovs-flow-logic
"""

import netaddr

from oslo_log import log as logging
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmpv6
from ryu.lib.packet import in_proto

from neutron._i18n import _LE
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge


LOG = logging.getLogger(__name__)


class OVSIntegrationBridge(ovs_bridge.OVSAgentBridge):
    """openvswitch agent br-int specific logic."""

    def setup_default_table(self):
        self.install_normal()
        self.setup_canary_table()
        self.install_drop(table_id=constants.ARP_SPOOF_TABLE)

    def setup_canary_table(self):
        self.install_drop(constants.CANARY_TABLE)

    def check_canary_table(self):
        try:
            flows = self.dump_flows(constants.CANARY_TABLE)
        except RuntimeError:
            LOG.exception(_LE("Failed to communicate with the switch"))
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
            ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
        ]
        self.install_apply_actions(priority=3,
                                   match=match,
                                   actions=actions)

    def reclaim_local_vlan(self, port, segmentation_id):
        (_dp, ofp, ofpp) = self._get_dp()
        if segmentation_id is None:
            vlan_vid = ofp.OFPVID_NONE
        else:
            vlan_vid = segmentation_id | ofp.OFPVID_PRESENT
        match = self._local_vlan_match(ofp, ofpp, port, vlan_vid)
        self.delete_flows(match=match)

    @staticmethod
    def _dvr_to_src_mac_match(ofp, ofpp, vlan_tag, dst_mac):
        return ofpp.OFPMatch(vlan_vid=vlan_tag | ofp.OFPVID_PRESENT,
                             eth_dst=dst_mac)

    @staticmethod
    def _dvr_to_src_mac_table_id(network_type):
        if network_type == p_const.TYPE_VLAN:
            return constants.DVR_TO_SRC_MAC_VLAN
        else:
            return constants.DVR_TO_SRC_MAC

    def install_dvr_to_src_mac(self, network_type,
                               vlan_tag, gateway_mac, dst_mac, dst_port):
        table_id = self._dvr_to_src_mac_table_id(network_type)
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_to_src_mac_match(ofp, ofpp,
                                           vlan_tag=vlan_tag, dst_mac=dst_mac)
        actions = [
            ofpp.OFPActionPopVlan(),
            ofpp.OFPActionSetField(eth_src=gateway_mac),
            ofpp.OFPActionOutput(dst_port, 0),
        ]
        self.install_apply_actions(table_id=table_id,
                                   priority=4,
                                   match=match,
                                   actions=actions)

    def delete_dvr_to_src_mac(self, network_type, vlan_tag, dst_mac):
        table_id = self._dvr_to_src_mac_table_id(network_type)
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._dvr_to_src_mac_match(ofp, ofpp,
                                           vlan_tag=vlan_tag, dst_mac=dst_mac)
        self.delete_flows(table_id=table_id, match=match)

    def add_dvr_mac_vlan(self, mac, port):
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=4,
                          in_port=port,
                          eth_src=mac,
                          dest_table_id=constants.DVR_TO_SRC_MAC_VLAN)

    def remove_dvr_mac_vlan(self, mac):
        # REVISIT(yamamoto): match in_port as well?
        self.delete_flows(table_id=constants.LOCAL_SWITCHING,
                          eth_src=mac)

    def add_dvr_mac_tun(self, mac, port):
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=2,
                          in_port=port,
                          eth_src=mac,
                          dest_table_id=constants.DVR_TO_SRC_MAC)

    def remove_dvr_mac_tun(self, mac, port):
        self.delete_flows(table_id=constants.LOCAL_SWITCHING,
                          in_port=port, eth_src=mac)

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
            masked_ip = self._cidr_to_ryu(ip)
            self.install_normal(
                table_id=constants.ARP_SPOOF_TABLE, priority=2,
                eth_type=ether_types.ETH_TYPE_IPV6,
                ip_proto=in_proto.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT,
                ipv6_nd_target=masked_ip, in_port=port)

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
            self.delete_flows(table_id=constants.LOCAL_SWITCHING, in_port=port)
            self.delete_flows(table_id=constants.MAC_SPOOF_TABLE, in_port=port)
            return
        mac_addresses = mac_addresses or []
        for address in mac_addresses:
            self.install_normal(
                table_id=constants.MAC_SPOOF_TABLE, priority=2,
                eth_src=address, in_port=port)
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
                self.delete_flows(table_id=constants.MAC_SPOOF_TABLE,
                                  in_port=port, eth_src=flow_mac)
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=9, in_port=port,
                          dest_table_id=constants.MAC_SPOOF_TABLE)

    def install_arp_spoofing_protection(self, port, ip_addresses):
        # allow ARP replies as long as they match addresses that actually
        # belong to the port.
        for ip in ip_addresses:
            masked_ip = self._cidr_to_ryu(ip)
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

    def delete_arp_spoofing_protection(self, port):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._arp_reply_match(ofp, ofpp, port=port)
        self.delete_flows(table_id=constants.LOCAL_SWITCHING,
                          match=match)
        match = self._icmpv6_reply_match(ofp, ofpp, port=port)
        self.delete_flows(table_id=constants.LOCAL_SWITCHING,
                          match=match)
        self.delete_arp_spoofing_allow_rules(port)

    def delete_arp_spoofing_allow_rules(self, port):
        self.delete_flows(table_id=constants.ARP_SPOOF_TABLE,
                          in_port=port)
