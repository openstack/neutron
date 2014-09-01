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

"""
OpenFlow1.3 flow table for OFAgent

* requirements
** plain OpenFlow 1.3. no vendor extensions.

* legends
 xxx: network id  (agent internal use)
 yyy: segment id  (vlan id, gre key, ...)
 a,b,c: tunnel port  (tun_ofports, map[net_id].tun_ofports)
 i,j,k: vm port  (map[net_id].vif_ports[vif_id].ofport)
 x,y,z: physical port  (int_ofports)
 N: tunnel type  (0 for TYPE_GRE, 1 for TYPE_xxx, ...)
 iii: unknown ip address
 uuu: unicast l2 address

* tables (in order)
    CHECK_IN_PORT
    TUNNEL_IN+N
    PHYS_IN
    LOCAL_IN
    ARP_PASSTHROUGH
    ARP_RESPONDER
    TUNNEL_OUT
    LOCAL_OUT
    PHYS_OUT
    TUNNEL_FLOOD+N
    PHYS_FLOOD
    LOCAL_FLOOD

* CHECK_IN_PORT

   for each vm ports:
      // check_in_port_add_local_port, check_in_port_delete_port
      in_port=i, write_metadata(LOCAL|xxx),goto(LOCAL_IN)
   TYPE_GRE
   for each tunnel ports:
      // check_in_port_add_tunnel_port, check_in_port_delete_port
      in_port=a, goto(TUNNEL_IN+N)
   TYPE_VLAN
   for each networks ports:
      // provision_tenant_physnet, reclaim_tenant_physnet
      in_port=x,vlan_vid=present|yyy, write_metadata(xxx),goto(PHYS_IN)
   TYPE_FLAT
      // provision_tenant_physnet, reclaim_tenant_physnet
      in_port=x, write_metadata(xxx),goto(PHYS_IN)
   default drop

* TUNNEL_IN+N  (per tunnel types)  tunnel -> network

   for each networks:
      // provision_tenant_tunnel, reclaim_tenant_tunnel
      tun_id=yyy, write_metadata(xxx),goto(TUNNEL_OUT)

   default drop

* PHYS_IN
   default goto(TUNNEL_OUT)

* LOCAL_IN
   default goto(next_table)

* ARP_PASSTHROUGH
   for each unknown tpa:
      // arp_passthrough
      arp,arp_op=request,metadata=xxx,tpa=iii, idle_timeout=5, goto(TUNNEL_OUT)
   default goto(next_table)

* ARP_RESPONDER
   arp,arp_op=request, output:controller
   default goto(next_table)

* TUNNEL_OUT
   TYPE_GRE
   // !FLOODING_ENTRY
   // install_tunnel_output, delete_tunnel_output
   metadata=LOCAL|xxx,eth_dst=uuu  set_tunnel(yyy),output:a

   default goto(next table)

* LOCAL_OUT
   for each known destinations:
      // local_out_add_port, local_out_delete_port
      metadata=xxx,eth_dst=uuu output:i
   default goto(next table)

* PHYS_OUT

   NOTE(yamamoto): currently this table is always empty.

   default goto(next table)

* TUNNEL_FLOOD+N. (per tunnel types)

   network -> tunnel/vlan
   output to tunnel/physical ports
   "next table" might be LOCAL_OUT
   TYPE_GRE
   for each networks:
      // FLOODING_ENTRY
      // install_tunnel_output, delete_tunnel_output
      metadata=LOCAL|xxx, set_tunnel(yyy),output:a,b,c,goto(next table)

   default goto(next table)

* PHYS_FLOOD

   TYPE_VLAN
   for each networks:
      // provision_tenant_physnet, reclaim_tenant_physnet
      metadata=LOCAL|xxx, push_vlan:0x8100,set_field:present|yyy->vlan_vid,
                    output:x,pop_vlan,goto(next table)
   TYPE_FLAT
   for each networks:
      // provision_tenant_physnet, reclaim_tenant_physnet
      metadata=LOCAL|xxx, output:x,goto(next table)

   default goto(next table)

* LOCAL_FLOOD

   for each networks:
      // local_flood_update, local_flood_delete
      metadata=xxx, output:i,j,k
      or
      metadata=xxx,eth_dst=broadcast, output:i,j,k

   default drop

* references
** OVS agent https://wiki.openstack.org/wiki/Ovs-flow-logic
*** we use metadata instead of "internal" VLANs
*** we don't want to use NX learn action
"""

from ryu.lib.packet import arp
from ryu.ofproto import ether

from neutron.plugins.common import constants as p_const
import neutron.plugins.ofagent.agent.metadata as meta
from neutron.plugins.ofagent.agent import ofswitch
from neutron.plugins.ofagent.agent import tables


class OFAgentIntegrationBridge(ofswitch.OpenFlowSwitch):
    """ofagent br-int specific logic."""

    def setup_default_table(self):
        self.delete_flows()

        self.install_default_drop(tables.CHECK_IN_PORT)

        for t in tables.TUNNEL_IN.values():
            self.install_default_drop(t)
        self.install_default_goto(tables.PHYS_IN, tables.TUNNEL_OUT)
        self.install_default_goto_next(tables.LOCAL_IN)
        self.install_default_goto_next(tables.ARP_PASSTHROUGH)
        self.install_arp_responder(tables.ARP_RESPONDER)

        self.install_default_goto_next(tables.TUNNEL_OUT)
        self.install_default_goto_next(tables.LOCAL_OUT)
        self.install_default_goto_next(tables.PHYS_OUT)

        for t in tables.TUNNEL_FLOOD.values():
            self.install_default_goto_next(t)
        self.install_default_goto_next(tables.PHYS_FLOOD)
        self.install_default_drop(tables.LOCAL_FLOOD)

    def install_arp_responder(self, table_id):
        (dp, ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(eth_type=ether.ETH_TYPE_ARP,
                              arp_op=arp.ARP_REQUEST)
        actions = [ofpp.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=table_id,
                              priority=1,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)
        self.install_default_goto_next(table_id)

    def install_tunnel_output(self, table_id,
                              network, segmentation_id,
                              ports, goto_next, **additional_matches):
        (dp, ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(metadata=meta.mk_metadata(network, meta.LOCAL),
                              **additional_matches)
        actions = [ofpp.OFPActionSetField(tunnel_id=segmentation_id)]
        actions += [ofpp.OFPActionOutput(port=p) for p in ports]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        if goto_next:
            instructions += [
                ofpp.OFPInstructionGotoTable(table_id=table_id + 1),
            ]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=table_id,
                              priority=1,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)

    def delete_tunnel_output(self, table_id,
                             network, **additional_matches):
        (dp, _ofp, ofpp) = self._get_dp()
        self.delete_flows(table_id=table_id,
                          metadata=meta.mk_metadata(network, meta.LOCAL),
                          **additional_matches)

    def provision_tenant_tunnel(self, network_type, network, segmentation_id):
        (dp, _ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(tunnel_id=segmentation_id)
        metadata = meta.mk_metadata(network)
        instructions = [
            ofpp.OFPInstructionWriteMetadata(metadata=metadata[0],
                                             metadata_mask=metadata[1]),
            ofpp.OFPInstructionGotoTable(table_id=tables.TUNNEL_OUT),
        ]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=tables.TUNNEL_IN[network_type],
                              priority=1,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)

    def reclaim_tenant_tunnel(self, network_type, network, segmentation_id):
        table_id = tables.TUNNEL_IN[network_type]
        self.delete_flows(table_id=table_id, tunnel_id=segmentation_id)

    def provision_tenant_physnet(self, network_type, network,
                                 segmentation_id, phys_port):
        """for vlan and flat."""
        assert(network_type in [p_const.TYPE_VLAN, p_const.TYPE_FLAT])
        (dp, ofp, ofpp) = self._get_dp()

        # inbound
        metadata = meta.mk_metadata(network)
        instructions = [
            ofpp.OFPInstructionWriteMetadata(metadata=metadata[0],
                                             metadata_mask=metadata[1])
        ]
        if network_type == p_const.TYPE_VLAN:
            vlan_vid = segmentation_id | ofp.OFPVID_PRESENT
            match = ofpp.OFPMatch(in_port=phys_port, vlan_vid=vlan_vid)
            actions = [ofpp.OFPActionPopVlan()]
            instructions += [ofpp.OFPInstructionActions(
                             ofp.OFPIT_APPLY_ACTIONS, actions)]
        else:
            match = ofpp.OFPMatch(in_port=phys_port)
        instructions += [ofpp.OFPInstructionGotoTable(table_id=tables.PHYS_IN)]
        msg = ofpp.OFPFlowMod(dp,
                              priority=1,
                              table_id=tables.CHECK_IN_PORT,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)

        # outbound
        match = ofpp.OFPMatch(metadata=meta.mk_metadata(network, meta.LOCAL))
        if network_type == p_const.TYPE_VLAN:
            actions = [
                ofpp.OFPActionPushVlan(),
                ofpp.OFPActionSetField(vlan_vid=vlan_vid),
            ]
        else:
            actions = []
        actions += [ofpp.OFPActionOutput(port=phys_port)]
        if network_type == p_const.TYPE_VLAN:
            actions += [ofpp.OFPActionPopVlan()]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
            ofpp.OFPInstructionGotoTable(table_id=tables.PHYS_FLOOD + 1),
        ]
        msg = ofpp.OFPFlowMod(dp,
                              priority=1,
                              table_id=tables.PHYS_FLOOD,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)

    def reclaim_tenant_physnet(self, network_type, network,
                               segmentation_id, phys_port):
        (_dp, ofp, _ofpp) = self._get_dp()
        vlan_vid = segmentation_id | ofp.OFPVID_PRESENT
        if network_type == p_const.TYPE_VLAN:
            self.delete_flows(table_id=tables.CHECK_IN_PORT,
                              in_port=phys_port, vlan_vid=vlan_vid)
        else:
            self.delete_flows(table_id=tables.CHECK_IN_PORT,
                              in_port=phys_port)
        self.delete_flows(table_id=tables.PHYS_FLOOD,
                          metadata=meta.mk_metadata(network))

    def check_in_port_add_tunnel_port(self, network_type, port):
        (dp, _ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(in_port=port)
        instructions = [
            ofpp.OFPInstructionGotoTable(
                table_id=tables.TUNNEL_IN[network_type])
        ]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=tables.CHECK_IN_PORT,
                              priority=1,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)

    def check_in_port_add_local_port(self, network, port):
        (dp, ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(in_port=port)
        metadata = meta.mk_metadata(network, meta.LOCAL)
        instructions = [
            ofpp.OFPInstructionWriteMetadata(metadata=metadata[0],
                                             metadata_mask=metadata[1]),
            ofpp.OFPInstructionGotoTable(table_id=tables.LOCAL_IN),
        ]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=tables.CHECK_IN_PORT,
                              priority=1,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)

    def check_in_port_delete_port(self, port):
        self.delete_flows(table_id=tables.CHECK_IN_PORT, in_port=port)

    def local_flood_update(self, network, ports, flood_unicast):
        (dp, ofp, ofpp) = self._get_dp()
        match_all = ofpp.OFPMatch(metadata=meta.mk_metadata(network))
        match_multicast = ofpp.OFPMatch(metadata=meta.mk_metadata(network),
                                        eth_dst=('01:00:00:00:00:00',
                                                 '01:00:00:00:00:00'))
        if flood_unicast:
            match_add = match_all
            match_del = match_multicast
        else:
            match_add = match_multicast
            match_del = match_all
        actions = [ofpp.OFPActionOutput(port=p) for p in ports]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=tables.LOCAL_FLOOD,
                              priority=1,
                              match=match_add,
                              instructions=instructions)
        self._send_msg(msg)
        self.delete_flows(table_id=tables.LOCAL_FLOOD, strict=True,
                          priority=1, match=match_del)

    def local_flood_delete(self, network):
        self.delete_flows(table_id=tables.LOCAL_FLOOD,
                          metadata=meta.mk_metadata(network))

    def local_out_add_port(self, network, port, mac):
        (dp, ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(metadata=meta.mk_metadata(network), eth_dst=mac)
        actions = [ofpp.OFPActionOutput(port=port)]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=tables.LOCAL_OUT,
                              priority=1,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)

    def local_out_delete_port(self, network, mac):
        self.delete_flows(table_id=tables.LOCAL_OUT,
                          metadata=meta.mk_metadata(network), eth_dst=mac)

    def arp_passthrough(self, network, tpa):
        (dp, ofp, ofpp) = self._get_dp()
        match = ofpp.OFPMatch(metadata=meta.mk_metadata(network),
                              eth_type=ether.ETH_TYPE_ARP,
                              arp_op=arp.ARP_REQUEST,
                              arp_tpa=tpa)
        instructions = [
            ofpp.OFPInstructionGotoTable(table_id=tables.TUNNEL_OUT)]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=tables.ARP_PASSTHROUGH,
                              priority=1,
                              idle_timeout=5,
                              match=match,
                              instructions=instructions)
        self._send_msg(msg)
