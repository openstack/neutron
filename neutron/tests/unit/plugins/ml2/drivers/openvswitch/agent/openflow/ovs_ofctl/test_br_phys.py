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
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent.\
    openflow.ovs_ofctl import ovs_bridge_test_base


call = mock.call  # short hand


class OVSPhysicalBridgeTest(ovs_bridge_test_base.OVSBridgeTestBase,
                            ovs_bridge_test_base.OVSDVRProcessTestMixin):
    dvr_process_table_id = ovs_const.DVR_PROCESS_VLAN
    dvr_process_next_table_id = ovs_const.LOCAL_VLAN_TRANSLATION

    def setUp(self):
        super(OVSPhysicalBridgeTest, self).setUp()
        self.setup_bridge_mock('br-phys', self.br_phys_cls)

    def test_setup_default_table(self):
        self.br.setup_default_table()
        expected = [
            call.add_flow(priority=0, table=0, actions='normal'),
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
        expected = [
            call.add_flow(priority=4, table=0, dl_vlan=lvid, in_port=port,
                          actions='mod_vlan_vid:%s,normal' % segmentation_id),
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
        expected = [
            call.add_flow(priority=4, table=0, dl_vlan=lvid, in_port=port,
                          actions='strip_vlan,normal')
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_reclaim_local_vlan(self):
        port = 999
        lvid = 888
        self.br.reclaim_local_vlan(port=port, lvid=lvid)
        expected = [
            call.delete_flows(dl_vlan=lvid, in_port=port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_add_dvr_mac_vlan(self):
        mac = '00:02:b3:13:fe:3d'
        port = 8888
        self.br.add_dvr_mac_vlan(mac=mac, port=port)
        expected = [
            call.add_flow(priority=2, table=3, dl_src=mac,
                          actions='output:%s' % port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_dvr_mac_vlan(self):
        mac = '00:02:b3:13:fe:3d'
        self.br.remove_dvr_mac_vlan(mac=mac)
        expected = [
            call.delete_flows(dl_src=mac, table=3),
        ]
        self.assertEqual(expected, self.mock.mock_calls)
