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

import functools

import netaddr

from neutron.agent.common import ovs_lib
from neutron.plugins.openvswitch.agent.openflow.ovs_ofctl import br_dvr_process
from neutron.plugins.openvswitch.agent.openflow.ovs_ofctl import ovs_bridge
from neutron.plugins.openvswitch.common import constants


class OVSTunnelBridge(ovs_bridge.OVSAgentBridge,
                      br_dvr_process.OVSDVRProcessMixin):
    """openvswitch agent tunnel bridge specific logic."""

    # Used by OVSDVRProcessMixin
    dvr_process_table_id = constants.DVR_PROCESS
    dvr_process_next_table_id = constants.PATCH_LV_TO_TUN

    def setup_default_table(self, patch_int_ofport, arp_responder_enabled):
        # Table 0 (default) will sort incoming traffic depending on in_port
        self.add_flow(priority=1,
                      in_port=patch_int_ofport,
                      actions="resubmit(,%s)" %
                      constants.PATCH_LV_TO_TUN)
        self.add_flow(priority=0, actions="drop")

        if arp_responder_enabled:
            # ARP broadcast-ed request go to the local ARP_RESPONDER table to
            # be locally resolved
            # REVISIT(yamamoto): arp_op=arp.ARP_REQUEST
            self.add_flow(table=constants.PATCH_LV_TO_TUN,
                          priority=1,
                          proto='arp',
                          dl_dst="ff:ff:ff:ff:ff:ff",
                          actions=("resubmit(,%s)" %
                                   constants.ARP_RESPONDER))

        # PATCH_LV_TO_TUN table will handle packets coming from patch_int
        # unicasts go to table UCAST_TO_TUN where remote addresses are learnt
        self.add_flow(table=constants.PATCH_LV_TO_TUN,
                      priority=0,
                      dl_dst="00:00:00:00:00:00/01:00:00:00:00:00",
                      actions="resubmit(,%s)" % constants.UCAST_TO_TUN)

        # Broadcasts/multicasts go to table FLOOD_TO_TUN that handles flooding
        self.add_flow(table=constants.PATCH_LV_TO_TUN,
                      priority=0,
                      dl_dst="01:00:00:00:00:00/01:00:00:00:00:00",
                      actions="resubmit(,%s)" % constants.FLOOD_TO_TUN)

        # Tables [tunnel_type]_TUN_TO_LV will set lvid depending on tun_id
        # for each tunnel type, and resubmit to table LEARN_FROM_TUN where
        # remote mac addresses will be learnt
        for tunnel_type in constants.TUNNEL_NETWORK_TYPES:
            self.add_flow(table=constants.TUN_TABLE[tunnel_type],
                          priority=0,
                          actions="drop")

        # LEARN_FROM_TUN table will have a single flow using a learn action to
        # dynamically set-up flows in UCAST_TO_TUN corresponding to remote mac
        # addresses (assumes that lvid has already been set by a previous flow)
        learned_flow = ("table=%s,"
                        "priority=1,"
                        "hard_timeout=300,"
                        "NXM_OF_VLAN_TCI[0..11],"
                        "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                        "load:0->NXM_OF_VLAN_TCI[],"
                        "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
                        "output:NXM_OF_IN_PORT[]" %
                        constants.UCAST_TO_TUN)
        # Once remote mac addresses are learnt, output packet to patch_int
        self.add_flow(table=constants.LEARN_FROM_TUN,
                      priority=1,
                      actions="learn(%s),output:%s" %
                      (learned_flow, patch_int_ofport))

        # Egress unicast will be handled in table UCAST_TO_TUN, where remote
        # mac addresses will be learned. For now, just add a default flow that
        # will resubmit unknown unicasts to table FLOOD_TO_TUN to treat them
        # as broadcasts/multicasts
        self.add_flow(table=constants.UCAST_TO_TUN,
                      priority=0,
                      actions="resubmit(,%s)" %
                      constants.FLOOD_TO_TUN)

        if arp_responder_enabled:
            # If none of the ARP entries correspond to the requested IP, the
            # broadcast-ed packet is resubmitted to the flooding table
            self.add_flow(table=constants.ARP_RESPONDER,
                          priority=0,
                          actions="resubmit(,%s)" %
                          constants.FLOOD_TO_TUN)

        # FLOOD_TO_TUN will handle flooding in tunnels based on lvid,
        # for now, add a default drop action
        self.install_drop(table_id=constants.FLOOD_TO_TUN)

    def provision_local_vlan(self, network_type, lvid, segmentation_id,
                             distributed=False):
        if distributed:
            table_id = constants.DVR_NOT_LEARN
        else:
            table_id = constants.LEARN_FROM_TUN
        self.add_flow(table=constants.TUN_TABLE[network_type],
                      priority=1,
                      tun_id=segmentation_id,
                      actions="mod_vlan_vid:%s,"
                      "resubmit(,%s)" %
                      (lvid, table_id))

    def reclaim_local_vlan(self, network_type, segmentation_id):
        self.delete_flows(table=constants.TUN_TABLE[network_type],
                          tun_id=segmentation_id)

    @staticmethod
    def _ofport_set_to_str(ports_set):
        return ",".join(map(str, ports_set))

    def install_flood_to_tun(self, vlan, tun_id, ports, deferred_br=None):
        br = deferred_br if deferred_br else self
        br.mod_flow(table=constants.FLOOD_TO_TUN,
                    dl_vlan=vlan,
                    actions="strip_vlan,set_tunnel:%s,output:%s" %
                    (tun_id, self._ofport_set_to_str(ports)))

    def delete_flood_to_tun(self, vlan, deferred_br=None):
        br = deferred_br if deferred_br else self
        br.delete_flows(table=constants.FLOOD_TO_TUN, dl_vlan=vlan)

    def install_unicast_to_tun(self, vlan, tun_id, port, mac,
                               deferred_br=None):
        br = deferred_br if deferred_br else self
        br.add_flow(table=constants.UCAST_TO_TUN,
                    priority=2,
                    dl_vlan=vlan,
                    dl_dst=mac,
                    actions="strip_vlan,set_tunnel:%s,output:%s" %
                    (tun_id, port))

    def delete_unicast_to_tun(self, vlan, mac, deferred_br=None):
        br = deferred_br if deferred_br else self
        if mac is None:
            br.delete_flows(table=constants.UCAST_TO_TUN,
                            dl_vlan=vlan)
        else:
            br.delete_flows(table=constants.UCAST_TO_TUN,
                            dl_vlan=vlan,
                            dl_dst=mac)

    def install_arp_responder(self, vlan, ip, mac, deferred_br=None):
        br = deferred_br if deferred_br else self
        actions = constants.ARP_RESPONDER_ACTIONS % {
            'mac': netaddr.EUI(mac, dialect=netaddr.mac_unix),
            'ip': netaddr.IPAddress(ip),
        }
        br.add_flow(table=constants.ARP_RESPONDER,
                    priority=1,
                    proto='arp',
                    dl_vlan=vlan,
                    nw_dst='%s' % ip,
                    actions=actions)

    def delete_arp_responder(self, vlan, ip, deferred_br=None):
        br = deferred_br if deferred_br else self
        if ip is None:
            br.delete_flows(table=constants.ARP_RESPONDER,
                            proto='arp',
                            dl_vlan=vlan)
        else:
            br.delete_flows(table=constants.ARP_RESPONDER,
                            proto='arp',
                            dl_vlan=vlan,
                            nw_dst='%s' % ip)

    def setup_tunnel_port(self, network_type, port, deferred_br=None):
        br = deferred_br if deferred_br else self
        br.add_flow(priority=1,
                    in_port=port,
                    actions="resubmit(,%s)" %
                    constants.TUN_TABLE[network_type])

    def cleanup_tunnel_port(self, port, deferred_br=None):
        br = deferred_br if deferred_br else self
        br.delete_flows(in_port=port)

    def add_dvr_mac_tun(self, mac, port):
        # Table DVR_NOT_LEARN ensures unique dvr macs in the cloud
        # are not learnt, as they may result in flow explosions
        self.install_output(table_id=constants.DVR_NOT_LEARN,
                            priority=1,
                            eth_src=mac,
                            port=port)

    def remove_dvr_mac_tun(self, mac):
        # REVISIT(yamamoto): match in_port as well?
        self.delete_flows(table_id=constants.DVR_NOT_LEARN,
                          eth_src=mac)

    def deferred(self):
        return DeferredOVSTunnelBridge(self)


class DeferredOVSTunnelBridge(ovs_lib.DeferredOVSBridge):
    _METHODS = [
        'install_unicast_to_tun',
        'delete_unicast_to_tun',
        'install_flood_to_tun',
        'delete_flood_to_tun',
        'install_arp_responder',
        'delete_arp_responder',
        'setup_tunnel_port',
        'cleanup_tunnel_port',
    ]

    def __getattr__(self, name):
        if name in self._METHODS:
            m = getattr(self.br, name)
            return functools.partial(m, deferred_br=self)
        return super(DeferredOVSTunnelBridge, self).__getattr__(name)
