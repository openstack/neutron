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

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent.\
    openflow.ovs_ofctl import ovs_bridge_test_base


call = mock.call  # short hand


class OVSIntegrationBridgeTest(ovs_bridge_test_base.OVSBridgeTestBase):
    def setUp(self):
        super(OVSIntegrationBridgeTest, self).setUp()
        self.setup_bridge_mock('br-int', self.br_int_cls)

    def test_setup_default_table(self):
        self.br.setup_default_table()
        expected = [
            call.delete_flows(),
            call.add_flow(priority=0, table=0, actions='normal'),
            call.add_flow(priority=0, table=23, actions='drop'),
            call.add_flow(priority=0, table=24, actions='drop'),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_provision_local_vlan(self):
        port = 999
        lvid = 888
        segmentation_id = 777
        self.br.provision_local_vlan(port=port, lvid=lvid,
                                     segmentation_id=segmentation_id)
        expected = [
            call.add_flow(priority=3, dl_vlan=segmentation_id,
                          in_port=port,
                          actions='mod_vlan_vid:%s,normal' % lvid),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_provision_local_vlan_novlan(self):
        port = 999
        lvid = 888
        segmentation_id = None
        self.br.provision_local_vlan(port=port, lvid=lvid,
                                     segmentation_id=segmentation_id)
        expected = [
            call.add_flow(priority=3, dl_vlan=0xffff,
                          in_port=port,
                          actions='mod_vlan_vid:%s,normal' % lvid),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_reclaim_local_vlan(self):
        port = 999
        segmentation_id = 777
        self.br.reclaim_local_vlan(port=port, segmentation_id=segmentation_id)
        expected = [
            call.delete_flows(dl_vlan=segmentation_id, in_port=port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_reclaim_local_vlan_novlan(self):
        port = 999
        segmentation_id = None
        self.br.reclaim_local_vlan(port=port, segmentation_id=segmentation_id)
        expected = [
            call.delete_flows(dl_vlan=0xffff, in_port=port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_to_src_mac(self):
        network_type = 'vxlan'
        vlan_tag = 1111
        gateway_mac = '08:60:6e:7f:74:e7'
        dst_mac = '00:02:b3:13:fe:3d'
        dst_port = 6666
        self.br.install_dvr_to_src_mac(network_type=network_type,
                                       vlan_tag=vlan_tag,
                                       gateway_mac=gateway_mac,
                                       dst_mac=dst_mac,
                                       dst_port=dst_port)
        expected = [
            call.add_flow(priority=4, table=1, dl_dst=dst_mac,
                          dl_vlan=vlan_tag,
                          actions='strip_vlan,mod_dl_src:%(mac)s,'
                          'output:%(port)s' % {
                              'mac': gateway_mac,
                              'port': dst_port,
                          }),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_to_src_mac(self):
        network_type = 'vxlan'
        vlan_tag = 1111
        dst_mac = '00:02:b3:13:fe:3d'
        self.br.delete_dvr_to_src_mac(network_type=network_type,
                                      vlan_tag=vlan_tag,
                                      dst_mac=dst_mac)
        expected = [
            call.delete_flows(table=1, dl_dst=dst_mac, dl_vlan=vlan_tag),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_to_src_mac_vlan(self):
        network_type = 'vlan'
        vlan_tag = 1111
        gateway_mac = '08:60:6e:7f:74:e7'
        dst_mac = '00:02:b3:13:fe:3d'
        dst_port = 6666
        self.br.install_dvr_to_src_mac(network_type=network_type,
                                       vlan_tag=vlan_tag,
                                       gateway_mac=gateway_mac,
                                       dst_mac=dst_mac,
                                       dst_port=dst_port)
        expected = [
            call.add_flow(priority=4, table=2, dl_dst=dst_mac,
                          dl_vlan=vlan_tag,
                          actions='strip_vlan,mod_dl_src:%(mac)s,'
                          'output:%(port)s' % {
                              'mac': gateway_mac,
                              'port': dst_port,
                          }),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_to_src_mac_vlan(self):
        network_type = 'vlan'
        vlan_tag = 1111
        dst_mac = '00:02:b3:13:fe:3d'
        self.br.delete_dvr_to_src_mac(network_type=network_type,
                                      vlan_tag=vlan_tag,
                                      dst_mac=dst_mac)
        expected = [
            call.delete_flows(table=2, dl_dst=dst_mac, dl_vlan=vlan_tag),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_add_dvr_mac_vlan(self):
        mac = '00:02:b3:13:fe:3d'
        port = 8888
        self.br.add_dvr_mac_vlan(mac=mac, port=port)
        expected = [
            call.add_flow(priority=4, table=0, actions='resubmit(,2)',
                          dl_src=mac, in_port=port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_dvr_mac_vlan(self):
        mac = '00:02:b3:13:fe:3d'
        self.br.remove_dvr_mac_vlan(mac=mac)
        expected = [
            call.delete_flows(eth_src=mac, table_id=0),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_add_dvr_mac_tun(self):
        mac = '00:02:b3:13:fe:3d'
        port = 8888
        self.br.add_dvr_mac_tun(mac=mac, port=port)
        expected = [
            call.add_flow(priority=2, table=0, actions='resubmit(,1)',
                          dl_src=mac, in_port=port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_remove_dvr_mac_tun(self):
        mac = '00:02:b3:13:fe:3d'
        port = 8888
        self.br.remove_dvr_mac_tun(mac=mac, port=port)
        expected = [
            call.delete_flows(eth_src=mac, table_id=0, in_port=port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_arp_spoofing_protection(self):
        port = 8888
        ip_addresses = ['192.0.2.1', '192.0.2.2/32']
        self.br.install_arp_spoofing_protection(port, ip_addresses)
        expected = [
            call.add_flow(proto='arp', actions='normal',
                          arp_spa='192.0.2.1',
                          priority=2, table=24, in_port=8888),
            call.add_flow(proto='arp', actions='normal',
                          arp_spa='192.0.2.2/32',
                          priority=2, table=24, in_port=8888),
            call.add_flow(priority=10, table=0, in_port=8888,
                          actions='resubmit(,24)', proto='arp')
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_arp_spoofing_protection(self):
        port = 8888
        self.br.delete_arp_spoofing_protection(port)
        expected = [
            call.delete_flows(table_id=0, in_port=8888, proto='arp'),
            call.delete_flows(table_id=24, in_port=8888),
        ]
        self.assertEqual(expected, self.mock.mock_calls)
