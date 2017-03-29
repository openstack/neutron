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

import mock

import neutron.plugins.ml2.drivers.openvswitch.agent.common.constants \
    as ovs_const
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge_test_base


call = mock.call  # short hand


class OVSPhysicalBridgeTest(ovs_bridge_test_base.OVSBridgeTestBase,
                            ovs_bridge_test_base.OVSDVRProcessTestMixin):
    dvr_process_table_id = ovs_const.DVR_PROCESS_VLAN
    dvr_process_next_table_id = ovs_const.LOCAL_VLAN_TRANSLATION

    def setUp(self):
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        super(OVSPhysicalBridgeTest, self).setUp()
        self.addCleanup(conn_patcher.stop)
        self.setup_bridge_mock('br-phys', self.br_phys_cls)
        self.stamp = self.br.default_cookie

    def test_setup_default_table(self):
        self.br.setup_default_table()
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(),
                priority=0,
                table_id=0),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_provision_local_vlan(self):
        port = 999
        lvid = 888
        segmentation_id = 777
        distributed = False
        self.br.provision_local_vlan(port=port, lvid=lvid,
                                     segmentation_id=segmentation_id,
                                     distributed=distributed)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionSetField(
                            vlan_vid=segmentation_id | ofp.OFPVID_PRESENT),
                        ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    in_port=port,
                    vlan_vid=lvid | ofp.OFPVID_PRESENT),
                priority=4,
                table_id=0),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_provision_local_vlan_novlan(self):
        port = 999
        lvid = 888
        segmentation_id = None
        distributed = False
        self.br.provision_local_vlan(port=port, lvid=lvid,
                                     segmentation_id=segmentation_id,
                                     distributed=distributed)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionPopVlan(),
                        ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(
                    in_port=port,
                    vlan_vid=lvid | ofp.OFPVID_PRESENT),
                priority=4,
                table_id=0),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_reclaim_local_vlan(self):
        port = 999
        lvid = 888
        self.br.reclaim_local_vlan(port=port, lvid=lvid)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(
                match=ofpp.OFPMatch(
                    in_port=port,
                    vlan_vid=lvid | ofp.OFPVID_PRESENT)),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_add_dvr_mac_vlan(self):
        mac = '00:02:b3:13:fe:3d'
        port = 8888
        self.br.add_dvr_mac_vlan(mac=mac, port=port)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call._send_msg(ofpp.OFPFlowMod(dp,
                cookie=self.stamp,
                instructions=[
                    ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        ofpp.OFPActionOutput(port, 0),
                    ]),
                ],
                match=ofpp.OFPMatch(eth_src=mac),
                priority=2,
                table_id=3),
                           active_bundle=None),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_dvr_mac_vlan(self):
        mac = '00:02:b3:13:fe:3d'
        self.br.remove_dvr_mac_vlan(mac=mac)
        (dp, ofp, ofpp) = self._get_dp()
        expected = [
            call.uninstall_flows(eth_src=mac, table_id=3),
        ]
        self.assertEqual(expected, self.mock.mock_calls)
