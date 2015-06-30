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

from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import ovs_bridge


class OVSIntegrationBridge(ovs_bridge.OVSAgentBridge):
    """openvswitch agent br-int specific logic."""

    def setup_default_table(self):
        self.delete_flows()
        self.install_normal()
        self.setup_canary_table()
        self.install_drop(table_id=constants.ARP_SPOOF_TABLE)

    def setup_canary_table(self):
        self.install_drop(constants.CANARY_TABLE)

    def check_canary_table(self):
        canary_flows = self.dump_flows(constants.CANARY_TABLE)
        if canary_flows == '':
            return constants.OVS_RESTARTED
        elif canary_flows is None:
            return constants.OVS_DEAD
        else:
            return constants.OVS_NORMAL

    def provision_local_vlan(self, port, lvid, segmentation_id):
        if segmentation_id is None:
            dl_vlan = 0xffff
        else:
            dl_vlan = segmentation_id
        self.add_flow(priority=3,
                      in_port=port,
                      dl_vlan=dl_vlan,
                      actions="mod_vlan_vid:%s,normal" % lvid)

    def reclaim_local_vlan(self, port, segmentation_id):
        if segmentation_id is None:
            dl_vlan = 0xffff
        else:
            dl_vlan = segmentation_id
        self.delete_flows(in_port=port, dl_vlan=dl_vlan)

    @staticmethod
    def _dvr_to_src_mac_table_id(network_type):
        if network_type == p_const.TYPE_VLAN:
            return constants.DVR_TO_SRC_MAC_VLAN
        else:
            return constants.DVR_TO_SRC_MAC

    def install_dvr_to_src_mac(self, network_type,
                               vlan_tag, gateway_mac, dst_mac, dst_port):
        table_id = self._dvr_to_src_mac_table_id(network_type)
        self.add_flow(table=table_id,
                      priority=4,
                      dl_vlan=vlan_tag,
                      dl_dst=dst_mac,
                      actions="strip_vlan,mod_dl_src:%s,"
                      "output:%s" % (gateway_mac, dst_port))

    def delete_dvr_to_src_mac(self, network_type, vlan_tag, dst_mac):
        table_id = self._dvr_to_src_mac_table_id(network_type)
        self.delete_flows(table=table_id,
                          dl_vlan=vlan_tag,
                          dl_dst=dst_mac)

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
        # Table LOCAL_SWITCHING will now sort DVR traffic from other
        # traffic depending on in_port
        self.install_goto(table_id=constants.LOCAL_SWITCHING,
                          priority=2,
                          in_port=port,
                          eth_src=mac,
                          dest_table_id=constants.DVR_TO_SRC_MAC)

    def remove_dvr_mac_tun(self, mac, port):
        self.delete_flows(table_id=constants.LOCAL_SWITCHING,
                          in_port=port, eth_src=mac)

    def install_arp_spoofing_protection(self, port, ip_addresses):
        # allow ARPs as long as they match addresses that actually
        # belong to the port.
        for ip in ip_addresses:
            self.install_normal(
                table_id=constants.ARP_SPOOF_TABLE, priority=2,
                proto='arp', arp_spa=ip, in_port=port)

        # Now that the rules are ready, direct ARP traffic from the port into
        # the anti-spoof table.
        # This strategy fails gracefully because OVS versions that can't match
        # on ARP headers will just process traffic normally.
        self.add_flow(table=constants.LOCAL_SWITCHING,
                      priority=10, proto='arp', in_port=port,
                      actions=("resubmit(,%s)" % constants.ARP_SPOOF_TABLE))

    def delete_arp_spoofing_protection(self, port):
        self.delete_flows(table_id=constants.LOCAL_SWITCHING,
                          in_port=port, proto='arp')
        self.delete_flows(table_id=constants.ARP_SPOOF_TABLE,
                          in_port=port)
