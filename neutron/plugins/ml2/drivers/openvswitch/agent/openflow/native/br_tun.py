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

# Copyright 2011 VMware, Inc.
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

from os_ken.lib.packet import arp
from os_ken.lib.packet import ether_types

from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
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

    def setup_default_table(self, patch_int_ofport, arp_responder_enabled):
        (dp, ofp, ofpp) = self._get_dp()

        # Table 0 (default) will sort incoming traffic depending on in_port
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
        self.install_apply_actions(table_id=constants.LEARN_FROM_TUN,
                                   priority=1,
                                   actions=actions)

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

    def install_arp_responder(self, vlan, ip, mac):
        (dp, ofp, ofpp) = self._get_dp()
        match = self._arp_responder_match(ofp, ofpp, vlan, ip)
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
        self.install_apply_actions(table_id=constants.ARP_RESPONDER,
                                   priority=1,
                                   match=match,
                                   actions=actions)

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

    def deferred(self):
        # REVISIT(yamamoto): This is for API compat with "ovs-ofctl"
        # interface.  Consider removing this mechanism when obsoleting
        # "ovs-ofctl" interface.
        # For "ovs-ofctl" interface, "deferred" mechanism would improve
        # performance by batching flow-mods with a single ovs-ofctl command
        # invocation.
        # On the other hand, for this "native" interface, the overheads of
        # each flow-mods are already minimum and batching doesn't make much
        # sense.  Thus this method is left as no-op.
        # It might be possible to send multiple flow-mods with a single
        # barrier.  But it's unclear that level of performance optimization
        # is desirable while it would certainly complicate error handling.
        return self

    def __enter__(self):
        # REVISIT(yamamoto): See the comment on deferred().
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # REVISIT(yamamoto): See the comment on deferred().
        pass
