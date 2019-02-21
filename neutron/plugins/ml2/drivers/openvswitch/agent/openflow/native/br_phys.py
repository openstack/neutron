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

from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import br_dvr_process
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge


class OVSPhysicalBridge(ovs_bridge.OVSAgentBridge,
                        br_dvr_process.OVSDVRProcessMixin):
    """openvswitch agent physical bridge specific logic."""

    # Used by OVSDVRProcessMixin
    dvr_process_table_id = constants.DVR_PROCESS_VLAN
    dvr_process_next_table_id = constants.LOCAL_VLAN_TRANSLATION

    def setup_default_table(self):
        self.install_normal()

    @staticmethod
    def _local_vlan_match(ofp, ofpp, port, lvid):
        return ofpp.OFPMatch(in_port=port, vlan_vid=lvid | ofp.OFPVID_PRESENT)

    def provision_local_vlan(self, port, lvid, segmentation_id, distributed):
        table_id = constants.LOCAL_VLAN_TRANSLATION if distributed else 0
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._local_vlan_match(ofp, ofpp, port, lvid)
        if segmentation_id is None:
            actions = [ofpp.OFPActionPopVlan()]
        else:
            vlan_vid = segmentation_id | ofp.OFPVID_PRESENT
            actions = [ofpp.OFPActionSetField(vlan_vid=vlan_vid)]
        actions += [ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
        self.install_apply_actions(table_id=table_id,
                                   priority=4,
                                   match=match,
                                   actions=actions)

    def reclaim_local_vlan(self, port, lvid):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._local_vlan_match(ofp, ofpp, port, lvid)
        self.uninstall_flows(match=match)

    def add_dvr_mac_vlan(self, mac, port):
        self.install_output(table_id=constants.DVR_NOT_LEARN_VLAN,
                            priority=2, eth_src=mac, port=port)

    def remove_dvr_mac_vlan(self, mac):
        # REVISIT(yamamoto): match in_port as well?
        self.uninstall_flows(
            table_id=constants.DVR_NOT_LEARN_VLAN,
            eth_src=mac)
