# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Nicira Networks, Inc.
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
#
# @author: Dave Lapsley, Nicira Networks, Inc.

import unittest

import mox

from quantum.agent.linux import ovs_lib
from quantum.agent.linux import utils
from quantum.plugins.openvswitch.agent import ovs_quantum_agent

# Useful global dummy variables.
NET_UUID = '3faeebfe-5d37-11e1-a64b-000c29d5f0a7'
LS_ID = '42'
LV_ID = 42
LV_IDS = [42, 43]
VIF_ID = '404deaec-5d37-11e1-a64b-000c29d5f0a8'
VIF_MAC = '3c:09:24:1e:78:23'
OFPORT_NUM = 1
VIF_PORT = ovs_lib.VifPort('port', OFPORT_NUM,
                           VIF_ID, VIF_MAC, 'switch')
VIF_PORTS = {LV_ID: VIF_PORT}
LVM = ovs_quantum_agent.LocalVLANMapping(LV_ID, 'gre', None, LS_ID, VIF_PORTS)
BCAST_MAC = "01:00:00:00:00:00/01:00:00:00:00:00"


class DummyPort:
    def __init__(self, interface_id):
        self.interface_id = interface_id


class DummyVlanBinding:
    def __init__(self, network_id, vlan_id):
        self.network_id = network_id
        self.vlan_id = vlan_id


class TunnelTest(unittest.TestCase):

    def setUp(self):
        self.mox = mox.Mox()

        self.INT_BRIDGE = 'integration_bridge'
        self.TUN_BRIDGE = 'tunnel_bridge'
        self.INT_OFPORT = 11111
        self.TUN_OFPORT = 22222

        self.mox.StubOutClassWithMocks(ovs_lib, 'OVSBridge')
        self.mock_int_bridge = ovs_lib.OVSBridge(self.INT_BRIDGE, 'sudo')
        self.mock_int_bridge.delete_port('patch-tun')
        self.mock_int_bridge.remove_all_flows()
        self.mock_int_bridge.add_flow(priority=1, actions='normal')

        self.mock_tun_bridge = ovs_lib.OVSBridge(self.TUN_BRIDGE, 'sudo')
        self.mock_tun_bridge.reset_bridge()
        self.mock_int_bridge.add_patch_port(
            'patch-tun', 'patch-int').AndReturn(self.TUN_OFPORT)
        self.mock_tun_bridge.add_patch_port(
            'patch-int', 'patch-tun').AndReturn(self.INT_OFPORT)
        self.mock_tun_bridge.remove_all_flows()
        self.mock_tun_bridge.add_flow(priority=1, actions='drop')

        self.mox.StubOutWithMock(utils, 'get_interface_mac')
        utils.get_interface_mac(self.INT_BRIDGE).AndReturn('000000000001')

    def tearDown(self):
        self.mox.UnsetStubs()

    def testConstruct(self):
        self.mox.ReplayAll()

        b = ovs_quantum_agent.OVSQuantumAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', {},
                                              'sudo', 2, True)
        self.mox.VerifyAll()

    def testProvisionLocalVlan(self):
        action_string = 'set_tunnel:%s,normal' % LS_ID
        self.mock_tun_bridge.add_flow(priority=4, in_port=self.INT_OFPORT,
                                      dl_vlan=LV_ID, actions=action_string)

        action_string = 'mod_vlan_vid:%s,output:%s' % (LV_ID, self.INT_OFPORT)
        self.mock_tun_bridge.add_flow(priority=3, tun_id=LS_ID,
                                      dl_dst=BCAST_MAC, actions=action_string)

        self.mox.ReplayAll()

        a = ovs_quantum_agent.OVSQuantumAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', {},
                                              'sudo', 2, True)
        a.available_local_vlans = set([LV_ID])
        a.provision_local_vlan(NET_UUID, 'gre', None, LS_ID)
        self.mox.VerifyAll()

    def testReclaimLocalVlan(self):
        self.mock_tun_bridge.delete_flows(tun_id=LVM.segmentation_id)

        self.mock_tun_bridge.delete_flows(dl_vlan=LVM.vlan)

        self.mox.ReplayAll()
        a = ovs_quantum_agent.OVSQuantumAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', {},
                                              'sudo', 2, True)
        a.available_local_vlans = set()
        a.local_vlan_map[NET_UUID] = LVM
        a.reclaim_local_vlan(NET_UUID, LVM)
        self.assertTrue(LVM.vlan in a.available_local_vlans)
        self.mox.VerifyAll()

    def testPortBound(self):
        self.mock_int_bridge.set_db_attribute('Port', VIF_PORT.port_name,
                                              'tag', str(LVM.vlan))
        self.mock_int_bridge.delete_flows(in_port=VIF_PORT.ofport)

        action_string = 'mod_vlan_vid:%s,normal' % LV_ID
        self.mock_tun_bridge.add_flow(priority=3, tun_id=LS_ID,
                                      dl_dst=VIF_PORT.vif_mac,
                                      actions=action_string)

        self.mox.ReplayAll()
        a = ovs_quantum_agent.OVSQuantumAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', {},
                                              'sudo', 2, True)
        a.local_vlan_map[NET_UUID] = LVM
        a.port_bound(VIF_PORT, NET_UUID, 'gre', None, LS_ID)
        self.mox.VerifyAll()

    def testPortUnbound(self):
        self.mock_tun_bridge.delete_flows(dl_dst=VIF_MAC, tun_id=LS_ID)
        self.mox.ReplayAll()
        a = ovs_quantum_agent.OVSQuantumAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', {},
                                              'sudo', 2, True)
        a.available_local_vlans = set([LV_ID])
        a.local_vlan_map[NET_UUID] = LVM
        a.port_unbound(VIF_ID, NET_UUID)
        self.mox.VerifyAll()

    def testPortDead(self):
        self.mock_int_bridge.set_db_attribute(
            'Port', VIF_PORT.port_name, 'tag', ovs_quantum_agent.DEAD_VLAN_TAG)

        self.mock_int_bridge.add_flow(priority=2, in_port=VIF_PORT.ofport,
                                      actions='drop')

        self.mox.ReplayAll()
        a = ovs_quantum_agent.OVSQuantumAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', {},
                                              'sudo', 2, True)
        a.available_local_vlans = set([LV_ID])
        a.local_vlan_map[NET_UUID] = LVM
        a.port_dead(VIF_PORT)
        self.mox.VerifyAll()
