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

import mox
from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.openstack.common import log
from neutron.plugins.openvswitch.agent import ovs_neutron_agent
from neutron.plugins.openvswitch.common import constants
from neutron.tests import base


# Useful global dummy variables.
NET_UUID = '3faeebfe-5d37-11e1-a64b-000c29d5f0a7'
LS_ID = 42
LV_ID = 42
LV_IDS = [42, 43]
VIF_ID = '404deaec-5d37-11e1-a64b-000c29d5f0a8'
VIF_MAC = '3c:09:24:1e:78:23'
OFPORT_NUM = 1
VIF_PORT = ovs_lib.VifPort('port', OFPORT_NUM,
                           VIF_ID, VIF_MAC, 'switch')
VIF_PORTS = {VIF_ID: VIF_PORT}
LVM = ovs_neutron_agent.LocalVLANMapping(LV_ID, 'gre', None, LS_ID, VIF_PORTS)
LVM_FLAT = ovs_neutron_agent.LocalVLANMapping(
    LV_ID, 'flat', 'net1', LS_ID, VIF_PORTS)
LVM_VLAN = ovs_neutron_agent.LocalVLANMapping(
    LV_ID, 'vlan', 'net1', LS_ID, VIF_PORTS)

TUN_OFPORTS = {constants.TYPE_GRE: {'ip1': '11', 'ip2': '12'}}

BCAST_MAC = "01:00:00:00:00:00/01:00:00:00:00:00"
UCAST_MAC = "00:00:00:00:00:00/01:00:00:00:00:00"


class DummyPort:
    def __init__(self, interface_id):
        self.interface_id = interface_id


class DummyVlanBinding:
    def __init__(self, network_id, vlan_id):
        self.network_id = network_id
        self.vlan_id = vlan_id


class TunnelTest(base.BaseTestCase):

    def setUp(self):
        super(TunnelTest, self).setUp()
        cfg.CONF.set_override('rpc_backend',
                              'neutron.openstack.common.rpc.impl_fake')
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        self.mox = mox.Mox()
        self.addCleanup(self.mox.UnsetStubs)

        self.INT_BRIDGE = 'integration_bridge'
        self.TUN_BRIDGE = 'tunnel_bridge'
        self.MAP_TUN_BRIDGE = 'tunnel_bridge_mapping'
        self.NET_MAPPING = {'net1': self.MAP_TUN_BRIDGE}
        self.INT_OFPORT = 11111
        self.TUN_OFPORT = 22222
        self.MAP_TUN_OFPORT = 33333
        self.VETH_MTU = None
        self.inta = self.mox.CreateMock(ip_lib.IPDevice)
        self.intb = self.mox.CreateMock(ip_lib.IPDevice)
        self.inta.link = self.mox.CreateMock(ip_lib.IpLinkCommand)
        self.intb.link = self.mox.CreateMock(ip_lib.IpLinkCommand)

        self.mox.StubOutClassWithMocks(ovs_lib, 'OVSBridge')
        self.mock_int_bridge = ovs_lib.OVSBridge(self.INT_BRIDGE, 'sudo')
        self.mock_int_bridge.get_local_port_mac().AndReturn('000000000001')
        self.mock_int_bridge.delete_port('patch-tun')
        self.mock_int_bridge.remove_all_flows()
        self.mock_int_bridge.add_flow(priority=1, actions='normal')

        self.mock_map_tun_bridge = ovs_lib.OVSBridge(
            self.MAP_TUN_BRIDGE, 'sudo')
        self.mock_map_tun_bridge.br_name = self.MAP_TUN_BRIDGE
        self.mock_map_tun_bridge.remove_all_flows()
        self.mock_map_tun_bridge.add_flow(priority=1, actions='normal')
        self.mock_int_bridge.delete_port('int-tunnel_bridge_mapping')
        self.mock_map_tun_bridge.delete_port('phy-tunnel_bridge_mapping')
        self.mock_int_bridge.add_port(self.inta)
        self.mock_map_tun_bridge.add_port(self.intb)
        self.inta.link.set_up()
        self.intb.link.set_up()

        self.mock_int_bridge.add_flow(priority=2, in_port=None, actions='drop')
        self.mock_map_tun_bridge.add_flow(
            priority=2, in_port=None, actions='drop')

        self.mock_tun_bridge = ovs_lib.OVSBridge(self.TUN_BRIDGE, 'sudo')
        self.mock_tun_bridge.reset_bridge()
        self.mock_int_bridge.add_patch_port(
            'patch-tun', 'patch-int').AndReturn(self.TUN_OFPORT)
        self.mock_tun_bridge.add_patch_port(
            'patch-int', 'patch-tun').AndReturn(self.INT_OFPORT)

        self.mock_tun_bridge.remove_all_flows()
        self.mock_tun_bridge.add_flow(priority=1,
                                      in_port=self.INT_OFPORT,
                                      actions="resubmit(,%s)" %
                                      constants.PATCH_LV_TO_TUN)
        self.mock_tun_bridge.add_flow(priority=0, actions='drop')
        self.mock_tun_bridge.add_flow(table=constants.PATCH_LV_TO_TUN,
                                      dl_dst=UCAST_MAC,
                                      actions="resubmit(,%s)" %
                                      constants.UCAST_TO_TUN)
        self.mock_tun_bridge.add_flow(table=constants.PATCH_LV_TO_TUN,
                                      dl_dst=BCAST_MAC,
                                      actions="resubmit(,%s)" %
                                      constants.FLOOD_TO_TUN)
        for tunnel_type in constants.TUNNEL_NETWORK_TYPES:
            self.mock_tun_bridge.add_flow(
                table=constants.TUN_TABLE[tunnel_type],
                priority=0,
                actions="drop")
        learned_flow = ("table=%s,"
                        "priority=1,"
                        "hard_timeout=300,"
                        "NXM_OF_VLAN_TCI[0..11],"
                        "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                        "load:0->NXM_OF_VLAN_TCI[],"
                        "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
                        "output:NXM_OF_IN_PORT[]" %
                        constants.UCAST_TO_TUN)
        self.mock_tun_bridge.add_flow(table=constants.LEARN_FROM_TUN,
                                      priority=1,
                                      actions="learn(%s),output:%s" %
                                      (learned_flow, self.INT_OFPORT))
        self.mock_tun_bridge.add_flow(table=constants.UCAST_TO_TUN,
                                      priority=0,
                                      actions="resubmit(,%s)" %
                                      constants.FLOOD_TO_TUN)
        self.mock_tun_bridge.add_flow(table=constants.FLOOD_TO_TUN,
                                      priority=0,
                                      actions="drop")

        self.mox.StubOutWithMock(ip_lib, 'device_exists')
        ip_lib.device_exists('tunnel_bridge_mapping', 'sudo').AndReturn(True)
        ip_lib.device_exists(
            'int-tunnel_bridge_mapping', 'sudo').AndReturn(True)

        self.mox.StubOutWithMock(ip_lib.IpLinkCommand, 'delete')
        ip_lib.IPDevice('int-tunnel_bridge_mapping').link.delete()

        self.mox.StubOutClassWithMocks(ip_lib, 'IPWrapper')
        ip_lib.IPWrapper('sudo').add_veth(
            'int-tunnel_bridge_mapping',
            'phy-tunnel_bridge_mapping').AndReturn([self.inta, self.intb])

        self.mox.StubOutWithMock(ovs_lib, 'get_bridges')
        ovs_lib.get_bridges('sudo').AndReturn([self.INT_BRIDGE,
                                               self.TUN_BRIDGE,
                                               self.MAP_TUN_BRIDGE])

    def test_construct(self):
        self.mox.ReplayAll()
        ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                          self.TUN_BRIDGE,
                                          '10.0.0.1', self.NET_MAPPING,
                                          'sudo', 2, ['gre'],
                                          self.VETH_MTU)
        self.mox.VerifyAll()

    def test_construct_vxlan(self):
        self.mox.StubOutWithMock(ovs_lib, 'get_installed_ovs_klm_version')
        ovs_lib.get_installed_ovs_klm_version().AndReturn("1.10")
        self.mox.StubOutWithMock(ovs_lib, 'get_installed_ovs_usr_version')
        ovs_lib.get_installed_ovs_usr_version('sudo').AndReturn("1.10")
        self.mox.ReplayAll()
        ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                          self.TUN_BRIDGE,
                                          '10.0.0.1', self.NET_MAPPING,
                                          'sudo', 2, ['vxlan'],
                                          self.VETH_MTU)
        self.mox.VerifyAll()

    def test_provision_local_vlan(self):
        ofports = ','.join(TUN_OFPORTS[constants.TYPE_GRE].values())
        self.mock_tun_bridge.mod_flow(table=constants.FLOOD_TO_TUN,
                                      priority=1,
                                      dl_vlan=LV_ID,
                                      actions="strip_vlan,"
                                      "set_tunnel:%s,output:%s" %
                                      (LS_ID, ofports))

        self.mock_tun_bridge.add_flow(table=constants.TUN_TABLE['gre'],
                                      priority=1,
                                      tun_id=LS_ID,
                                      actions="mod_vlan_vid:%s,resubmit(,%s)" %
                                      (LV_ID, constants.LEARN_FROM_TUN))
        self.mox.ReplayAll()

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set([LV_ID])
        a.tun_br_ofports = TUN_OFPORTS
        a.provision_local_vlan(NET_UUID, constants.TYPE_GRE, None, LS_ID)
        self.mox.VerifyAll()

    def test_provision_local_vlan_flat(self):
        action_string = 'strip_vlan,normal'
        self.mock_map_tun_bridge.add_flow(
            priority=4, in_port=self.MAP_TUN_OFPORT,
            dl_vlan=LV_ID, actions=action_string)

        action_string = 'mod_vlan_vid:%s,normal' % LV_ID
        self.mock_int_bridge.add_flow(priority=3, in_port=self.INT_OFPORT,
                                      dl_vlan=65535, actions=action_string)

        self.mox.ReplayAll()

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set([LV_ID])
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT
        a.provision_local_vlan(NET_UUID, constants.TYPE_FLAT, 'net1', LS_ID)
        self.mox.VerifyAll()

    def test_provision_local_vlan_flat_fail(self):
        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.provision_local_vlan(NET_UUID, constants.TYPE_FLAT, 'net2', LS_ID)
        self.mox.VerifyAll()

    def test_provision_local_vlan_vlan(self):
        action_string = 'mod_vlan_vid:%s,normal' % LS_ID
        self.mock_map_tun_bridge.add_flow(
            priority=4, in_port=self.MAP_TUN_OFPORT,
            dl_vlan=LV_ID, actions=action_string)

        action_string = 'mod_vlan_vid:%s,normal' % LS_ID
        self.mock_int_bridge.add_flow(priority=3, in_port=self.INT_OFPORT,
                                      dl_vlan=LV_ID, actions=action_string)

        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set([LV_ID])
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT
        a.provision_local_vlan(NET_UUID, constants.TYPE_VLAN, 'net1', LS_ID)
        self.mox.VerifyAll()

    def test_provision_local_vlan_vlan_fail(self):
        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.provision_local_vlan(NET_UUID, constants.TYPE_VLAN, 'net2', LS_ID)
        self.mox.VerifyAll()

    def test_reclaim_local_vlan(self):
        self.mock_tun_bridge.delete_flows(
            table=constants.TUN_TABLE['gre'], tun_id=LS_ID)
        self.mock_tun_bridge.delete_flows(dl_vlan=LVM.vlan)

        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set()
        a.local_vlan_map[NET_UUID] = LVM
        a.reclaim_local_vlan(NET_UUID)
        self.assertTrue(LVM.vlan in a.available_local_vlans)
        self.mox.VerifyAll()

    def test_reclaim_local_vlan_flat(self):
        self.mock_map_tun_bridge.delete_flows(
            in_port=self.MAP_TUN_OFPORT, dl_vlan=LVM_FLAT.vlan)

        self.mock_int_bridge.delete_flows(
            dl_vlan=65535, in_port=self.INT_OFPORT)

        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT

        a.available_local_vlans = set()
        a.local_vlan_map[NET_UUID] = LVM_FLAT
        a.reclaim_local_vlan(NET_UUID)
        self.assertTrue(LVM_FLAT.vlan in a.available_local_vlans)
        self.mox.VerifyAll()

    def test_reclaim_local_vlan_vlan(self):
        self.mock_map_tun_bridge.delete_flows(
            in_port=self.MAP_TUN_OFPORT, dl_vlan=LVM_VLAN.vlan)

        self.mock_int_bridge.delete_flows(
            dl_vlan=LV_ID, in_port=self.INT_OFPORT)

        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT

        a.available_local_vlans = set()
        a.local_vlan_map[NET_UUID] = LVM_VLAN
        a.reclaim_local_vlan(NET_UUID)
        self.assertTrue(LVM_VLAN.vlan in a.available_local_vlans)
        self.mox.VerifyAll()

    def test_port_bound(self):
        self.mock_int_bridge.set_db_attribute('Port', VIF_PORT.port_name,
                                              'tag', str(LVM.vlan))
        self.mock_int_bridge.delete_flows(in_port=VIF_PORT.ofport)

        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.local_vlan_map[NET_UUID] = LVM
        a.port_bound(VIF_PORT, NET_UUID, 'gre', None, LS_ID)
        self.mox.VerifyAll()

    def test_port_unbound(self):
        self.mox.StubOutWithMock(
            ovs_neutron_agent.OVSNeutronAgent, 'reclaim_local_vlan')
        ovs_neutron_agent.OVSNeutronAgent.reclaim_local_vlan(NET_UUID)

        self.mox.ReplayAll()

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.local_vlan_map[NET_UUID] = LVM
        a.port_unbound(VIF_ID, NET_UUID)
        self.mox.VerifyAll()

    def test_port_dead(self):
        self.mock_int_bridge.set_db_attribute(
            'Port', VIF_PORT.port_name, 'tag', ovs_neutron_agent.DEAD_VLAN_TAG)

        self.mock_int_bridge.add_flow(priority=2, in_port=VIF_PORT.ofport,
                                      actions='drop')

        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set([LV_ID])
        a.local_vlan_map[NET_UUID] = LVM
        a.port_dead(VIF_PORT)
        self.mox.VerifyAll()

    def test_tunnel_update(self):
        self.mock_tun_bridge.add_tunnel_port('gre-1', '10.0.10.1', '10.0.0.1',
                                             'gre', 4789)
        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.tunnel_update(
            mox.MockAnything, tunnel_id='1', tunnel_ip='10.0.10.1',
            tunnel_type=constants.TYPE_GRE)
        self.mox.VerifyAll()

    def test_tunnel_update_self(self):
        self.mox.ReplayAll()
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.tunnel_update(
            mox.MockAnything, tunnel_id='1', tunnel_ip='10.0.0.1')
        self.mox.VerifyAll()

    def test_daemon_loop(self):
        reply2 = {'current': set(['tap0']),
                  'added': set([]),
                  'removed': set([])}

        reply3 = {'current': set(['tap2']),
                  'added': set([]),
                  'removed': set([])}

        self.mox.StubOutWithMock(log.ContextAdapter, 'exception')
        log.ContextAdapter.exception(
            _("Error in agent event loop")).AndRaise(
                Exception('Fake exception to get out of the loop'))

        self.mox.StubOutWithMock(
            ovs_neutron_agent.OVSNeutronAgent, 'update_ports')
        ovs_neutron_agent.OVSNeutronAgent.update_ports(set()).AndReturn(reply2)
        ovs_neutron_agent.OVSNeutronAgent.update_ports(
            set(['tap0'])).AndReturn(reply3)
        self.mox.StubOutWithMock(
            ovs_neutron_agent.OVSNeutronAgent, 'process_network_ports')
        ovs_neutron_agent.OVSNeutronAgent.process_network_ports(
            {'current': set(['tap0']),
             'removed': set([]),
             'added': set([])}).AndReturn(False)
        ovs_neutron_agent.OVSNeutronAgent.process_network_ports(
            {'current': set(['tap0']),
             'removed': set([]),
             'added': set([])}).AndRaise(
                 Exception('Fake exception to get out of the loop'))
        self.mox.ReplayAll()
        q_agent = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                                    self.TUN_BRIDGE,
                                                    '10.0.0.1',
                                                    self.NET_MAPPING,
                                                    'sudo', 2, ['gre'],
                                                    self.VETH_MTU)

        # Hack to test loop
        # We start method and expect it will raise after 2nd loop
        # If something goes wrong, mox.VerifyAll() will catch it
        try:
            q_agent.daemon_loop()
        except Exception:
            pass

        self.mox.VerifyAll()


class TunnelTestWithMTU(TunnelTest):

    def setUp(self):
        super(TunnelTestWithMTU, self).setUp()
        self.VETH_MTU = 1500
        self.inta.link.set_mtu(self.VETH_MTU)
        self.intb.link.set_mtu(self.VETH_MTU)
