# Copyright 2012 VMware, Inc.
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

import contextlib

import mock
from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
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

TUN_OFPORTS = {p_const.TYPE_GRE: {'ip1': '11', 'ip2': '12'}}

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
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_override('rpc_backend',
                              'neutron.openstack.common.rpc.impl_fake')
        cfg.CONF.set_override('report_interval', 0, 'AGENT')

        self.INT_BRIDGE = 'integration_bridge'
        self.TUN_BRIDGE = 'tunnel_bridge'
        self.MAP_TUN_BRIDGE = 'tun_br_map'
        self.NET_MAPPING = {'net1': self.MAP_TUN_BRIDGE}
        self.INT_OFPORT = 11111
        self.TUN_OFPORT = 22222
        self.MAP_TUN_OFPORT = 33333
        self.VETH_MTU = None
        self.inta = mock.Mock()
        self.intb = mock.Mock()

        self.ovs_bridges = {self.INT_BRIDGE: mock.Mock(),
                            self.TUN_BRIDGE: mock.Mock(),
                            self.MAP_TUN_BRIDGE: mock.Mock(),
                            }

        self.mock_bridge = mock.patch.object(ovs_lib, 'OVSBridge').start()
        self.mock_bridge.side_effect = (lambda br_name, root_helper:
                                        self.ovs_bridges[br_name])
        self.mock_bridge_expected = [
            mock.call(self.INT_BRIDGE, 'sudo'),
            mock.call(self.MAP_TUN_BRIDGE, 'sudo'),
            mock.call(self.TUN_BRIDGE, 'sudo'),
        ]

        self.mock_int_bridge = self.ovs_bridges[self.INT_BRIDGE]
        self.mock_int_bridge.get_local_port_mac.return_value = '000000000001'
        self.mock_int_bridge_expected = [
            mock.call.create(),
            mock.call.set_secure_mode(),
            mock.call.delete_port('patch-tun'),
            mock.call.remove_all_flows(),
            mock.call.add_flow(priority=1, actions='normal'),
            mock.call.add_flow(priority=0, table=constants.CANARY_TABLE,
                               actions='drop'),
            mock.call.get_local_port_mac()
        ]

        self.mock_map_tun_bridge = self.ovs_bridges[self.MAP_TUN_BRIDGE]
        self.mock_map_tun_bridge.br_name = self.MAP_TUN_BRIDGE
        self.mock_map_tun_bridge.add_port.return_value = None
        self.mock_map_tun_bridge_expected = [
            mock.call.remove_all_flows(),
            mock.call.add_flow(priority=1, actions='normal'),
            mock.call.delete_port('phy-%s' % self.MAP_TUN_BRIDGE),
            mock.call.add_port(self.intb),
        ]
        self.mock_int_bridge.add_port.return_value = None
        self.mock_int_bridge_expected += [
            mock.call.delete_port('int-%s' % self.MAP_TUN_BRIDGE),
            mock.call.add_port(self.inta)
        ]
        self.inta_expected = [mock.call.link.set_up()]
        self.intb_expected = [mock.call.link.set_up()]

        self.mock_int_bridge_expected += [
            mock.call.add_flow(priority=2, in_port=None, actions='drop')
        ]
        self.mock_map_tun_bridge_expected += [
            mock.call.add_flow(priority=2, in_port=None, actions='drop')
        ]

        self.mock_tun_bridge = self.ovs_bridges[self.TUN_BRIDGE]
        self.mock_tun_bridge_expected = [
            mock.call.reset_bridge(),
            mock.call.add_patch_port('patch-int', 'patch-tun'),
        ]
        self.mock_int_bridge_expected += [
            mock.call.add_patch_port('patch-tun', 'patch-int')
        ]
        self.mock_int_bridge.add_patch_port.return_value = self.TUN_OFPORT
        self.mock_tun_bridge.add_patch_port.return_value = self.INT_OFPORT

        self.mock_tun_bridge_expected += [
            mock.call.remove_all_flows(),
            mock.call.add_flow(priority=1,
                               in_port=self.INT_OFPORT,
                               actions="resubmit(,%s)" %
                               constants.PATCH_LV_TO_TUN),
            mock.call.add_flow(priority=0, actions='drop'),
            mock.call.add_flow(table=constants.PATCH_LV_TO_TUN,
                               dl_dst=UCAST_MAC,
                               actions="resubmit(,%s)" %
                               constants.UCAST_TO_TUN),
            mock.call.add_flow(table=constants.PATCH_LV_TO_TUN,
                               dl_dst=BCAST_MAC,
                               actions="resubmit(,%s)" %
                               constants.FLOOD_TO_TUN),
        ]
        for tunnel_type in constants.TUNNEL_NETWORK_TYPES:
            self.mock_tun_bridge_expected.append(
                mock.call.add_flow(
                    table=constants.TUN_TABLE[tunnel_type],
                    priority=0,
                    actions="drop"))
        learned_flow = ("table=%s,"
                        "priority=1,"
                        "hard_timeout=300,"
                        "NXM_OF_VLAN_TCI[0..11],"
                        "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                        "load:0->NXM_OF_VLAN_TCI[],"
                        "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
                        "output:NXM_OF_IN_PORT[]" %
                        constants.UCAST_TO_TUN)
        self.mock_tun_bridge_expected += [
            mock.call.add_flow(table=constants.LEARN_FROM_TUN,
                               priority=1,
                               actions="learn(%s),output:%s" %
                               (learned_flow, self.INT_OFPORT)),
            mock.call.add_flow(table=constants.UCAST_TO_TUN,
                               priority=0,
                               actions="resubmit(,%s)" %
                               constants.FLOOD_TO_TUN),
            mock.call.add_flow(table=constants.FLOOD_TO_TUN,
                               priority=0,
                               actions="drop")
        ]

        self.device_exists = mock.patch.object(ip_lib, 'device_exists').start()
        self.device_exists.return_value = True
        self.device_exists_expected = [
            mock.call(self.MAP_TUN_BRIDGE, 'sudo'),
            mock.call('int-%s' % self.MAP_TUN_BRIDGE, 'sudo'),
        ]

        self.ipdevice = mock.patch.object(ip_lib, 'IPDevice').start()
        self.ipdevice_expected = [
            mock.call('int-%s' % self.MAP_TUN_BRIDGE, 'sudo'),
            mock.call().link.delete()
        ]
        self.ipwrapper = mock.patch.object(ip_lib, 'IPWrapper').start()
        add_veth = self.ipwrapper.return_value.add_veth
        add_veth.return_value = [self.inta, self.intb]
        self.ipwrapper_expected = [
            mock.call('sudo'),
            mock.call().add_veth('int-%s' % self.MAP_TUN_BRIDGE,
                                 'phy-%s' % self.MAP_TUN_BRIDGE)
        ]

        self.get_bridges = mock.patch.object(ovs_lib, 'get_bridges').start()
        self.get_bridges.return_value = [self.INT_BRIDGE,
                                         self.TUN_BRIDGE,
                                         self.MAP_TUN_BRIDGE]
        self.get_bridges_expected = [
            mock.call('sudo')
        ]
        self.execute = mock.patch('neutron.agent.linux.utils.execute').start()
        self.execute_expected = [mock.call(['/sbin/udevadm', 'settle',
                                            '--timeout=10'])]

    def _verify_mock_call(self, mock_obj, expected):
        mock_obj.assert_has_calls(expected)
        self.assertEqual(len(mock_obj.mock_calls), len(expected))

    def _verify_mock_calls(self):
        self._verify_mock_call(self.mock_bridge, self.mock_bridge_expected)
        self._verify_mock_call(self.mock_int_bridge,
                               self.mock_int_bridge_expected)
        self._verify_mock_call(self.mock_map_tun_bridge,
                               self.mock_map_tun_bridge_expected)
        self._verify_mock_call(self.mock_tun_bridge,
                               self.mock_tun_bridge_expected)
        self._verify_mock_call(self.device_exists, self.device_exists_expected)
        self._verify_mock_call(self.ipdevice, self.ipdevice_expected)
        self._verify_mock_call(self.ipwrapper, self.ipwrapper_expected)
        self._verify_mock_call(self.get_bridges, self.get_bridges_expected)
        self._verify_mock_call(self.inta, self.inta_expected)
        self._verify_mock_call(self.intb, self.intb_expected)
        self._verify_mock_call(self.execute, self.execute_expected)

    def test_construct(self):
        ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                          self.TUN_BRIDGE,
                                          '10.0.0.1', self.NET_MAPPING,
                                          'sudo', 2, ['gre'],
                                          self.VETH_MTU)
        self._verify_mock_calls()

    def test_construct_vxlan(self):
        with mock.patch.object(ovs_lib, 'get_installed_ovs_klm_version',
                               return_value="1.10") as klm_ver:
            with mock.patch.object(ovs_lib, 'get_installed_ovs_usr_version',
                                   return_value="1.10") as usr_ver:
                with mock.patch.object(ovs_lib, 'get_installed_kernel_version',
                                       return_value=(
                                           constants.
                                           MINIMUM_LINUX_KERNEL_OVS_VXLAN
                                       )) as kernel_ver:
                    ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                                      self.TUN_BRIDGE,
                                                      '10.0.0.1',
                                                      self.NET_MAPPING,
                                                      'sudo', 2, ['vxlan'],
                                                      self.VETH_MTU)
        klm_ver.assert_called_once_with()
        kernel_ver.assert_called_once_with()
        usr_ver.assert_called_once_with('sudo')
        self._verify_mock_calls()

    def test_provision_local_vlan(self):
        ofports = ','.join(TUN_OFPORTS[p_const.TYPE_GRE].values())
        self.mock_tun_bridge_expected += [
            mock.call.mod_flow(table=constants.FLOOD_TO_TUN,
                               dl_vlan=LV_ID,
                               actions="strip_vlan,"
                               "set_tunnel:%s,output:%s" %
                               (LS_ID, ofports)),
            mock.call.add_flow(table=constants.TUN_TABLE['gre'],
                               priority=1,
                               tun_id=LS_ID,
                               actions="mod_vlan_vid:%s,resubmit(,%s)" %
                               (LV_ID, constants.LEARN_FROM_TUN)),
        ]

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set([LV_ID])
        a.tun_br_ofports = TUN_OFPORTS
        a.provision_local_vlan(NET_UUID, p_const.TYPE_GRE, None, LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_flat(self):
        action_string = 'strip_vlan,normal'
        self.mock_map_tun_bridge_expected.append(
            mock.call.add_flow(priority=4, in_port=self.MAP_TUN_OFPORT,
                               dl_vlan=LV_ID, actions=action_string))

        action_string = 'mod_vlan_vid:%s,normal' % LV_ID
        self.mock_int_bridge_expected.append(
            mock.call.add_flow(priority=3, in_port=self.INT_OFPORT,
                               dl_vlan=65535, actions=action_string))

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set([LV_ID])
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT
        a.provision_local_vlan(NET_UUID, p_const.TYPE_FLAT, 'net1', LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_flat_fail(self):
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.provision_local_vlan(NET_UUID, p_const.TYPE_FLAT, 'net2', LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_vlan(self):
        action_string = 'mod_vlan_vid:%s,normal' % LS_ID
        self.mock_map_tun_bridge_expected.append(
            mock.call.add_flow(priority=4, in_port=self.MAP_TUN_OFPORT,
                               dl_vlan=LV_ID, actions=action_string))

        action_string = 'mod_vlan_vid:%s,normal' % LS_ID
        self.mock_int_bridge_expected.append(
            mock.call.add_flow(priority=3, in_port=self.INT_OFPORT,
                               dl_vlan=LV_ID, actions=action_string))

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set([LV_ID])
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT
        a.provision_local_vlan(NET_UUID, p_const.TYPE_VLAN, 'net1', LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_vlan_fail(self):
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.provision_local_vlan(NET_UUID, p_const.TYPE_VLAN, 'net2', LS_ID)
        self._verify_mock_calls()

    def test_reclaim_local_vlan(self):
        self.mock_tun_bridge_expected += [
            mock.call.delete_flows(
                table=constants.TUN_TABLE['gre'], tun_id=LS_ID),
            mock.call.delete_flows(dl_vlan=LVM.vlan)
        ]

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set()
        a.local_vlan_map[NET_UUID] = LVM
        a.reclaim_local_vlan(NET_UUID)
        self.assertIn(LVM.vlan, a.available_local_vlans)
        self._verify_mock_calls()

    def test_reclaim_local_vlan_flat(self):
        self.mock_map_tun_bridge_expected.append(
            mock.call.delete_flows(
                in_port=self.MAP_TUN_OFPORT, dl_vlan=LVM_FLAT.vlan))
        self.mock_int_bridge_expected.append(
            mock.call.delete_flows(
                dl_vlan=65535, in_port=self.INT_OFPORT))

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
        self.assertIn(LVM_FLAT.vlan, a.available_local_vlans)
        self._verify_mock_calls()

    def test_reclaim_local_vlan_vlan(self):
        self.mock_map_tun_bridge_expected.append(
            mock.call.delete_flows(
                in_port=self.MAP_TUN_OFPORT, dl_vlan=LVM_VLAN.vlan))
        self.mock_int_bridge_expected.append(
            mock.call.delete_flows(
                dl_vlan=LV_ID, in_port=self.INT_OFPORT))

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
        self.assertIn(LVM_VLAN.vlan, a.available_local_vlans)
        self._verify_mock_calls()

    def test_port_bound(self):
        self.mock_int_bridge_expected += [
            mock.call.db_get_val('Port', VIF_PORT.port_name, 'tag'),
            mock.call.set_db_attribute('Port', VIF_PORT.port_name,
                                       'tag', str(LVM.vlan)),
            mock.call.delete_flows(in_port=VIF_PORT.ofport)
        ]

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.local_vlan_map[NET_UUID] = LVM
        a.port_bound(VIF_PORT, NET_UUID, 'gre', None, LS_ID, False)
        self._verify_mock_calls()

    def test_port_unbound(self):
        with mock.patch.object(ovs_neutron_agent.OVSNeutronAgent,
                               'reclaim_local_vlan') as reclaim_local_vlan:
            a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                                  self.TUN_BRIDGE,
                                                  '10.0.0.1', self.NET_MAPPING,
                                                  'sudo', 2, ['gre'],
                                                  self.VETH_MTU)
            a.local_vlan_map[NET_UUID] = LVM
            a.port_unbound(VIF_ID, NET_UUID)

        reclaim_local_vlan.assert_called_once_with(NET_UUID)
        self._verify_mock_calls()

    def test_port_dead(self):
        self.mock_int_bridge_expected += [
            mock.call.db_get_val('Port', VIF_PORT.port_name, 'tag'),
            mock.call.set_db_attribute(
                'Port', VIF_PORT.port_name,
                'tag', ovs_neutron_agent.DEAD_VLAN_TAG),
            mock.call.add_flow(priority=2, in_port=VIF_PORT.ofport,
                               actions='drop')
        ]

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.available_local_vlans = set([LV_ID])
        a.local_vlan_map[NET_UUID] = LVM
        a.port_dead(VIF_PORT)
        self._verify_mock_calls()

    def test_tunnel_update(self):
        tunnel_port = '9999'
        self.mock_tun_bridge.add_tunnel_port.return_value = tunnel_port
        self.mock_tun_bridge_expected += [
            mock.call.add_tunnel_port('gre-1', '10.0.10.1', '10.0.0.1',
                                      'gre', 4789),
            mock.call.add_flow(priority=1, in_port=tunnel_port,
                               actions='resubmit(,2)')
        ]

        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.tunnel_update(
            mock.sentinel.ctx, tunnel_id='1', tunnel_ip='10.0.10.1',
            tunnel_type=p_const.TYPE_GRE)
        self._verify_mock_calls()

    def test_tunnel_update_self(self):
        a = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                              self.TUN_BRIDGE,
                                              '10.0.0.1', self.NET_MAPPING,
                                              'sudo', 2, ['gre'],
                                              self.VETH_MTU)
        a.tunnel_update(
            mock.sentinel.ctx, tunnel_id='1', tunnel_ip='10.0.0.1')
        self._verify_mock_calls()

    def test_daemon_loop(self):
        reply2 = {'current': set(['tap0']),
                  'added': set(['tap2']),
                  'removed': set([])}

        reply3 = {'current': set(['tap2']),
                  'added': set([]),
                  'removed': set(['tap0'])}

        self.mock_int_bridge_expected += [
            mock.call.dump_flows_for_table(constants.CANARY_TABLE),
            mock.call.dump_flows_for_table(constants.CANARY_TABLE)
        ]

        with contextlib.nested(
            mock.patch.object(log.ContextAdapter, 'exception'),
            mock.patch.object(ovs_neutron_agent.OVSNeutronAgent,
                              'scan_ports'),
            mock.patch.object(ovs_neutron_agent.OVSNeutronAgent,
                              'process_network_ports')
        ) as (log_exception, scan_ports, process_network_ports):
            log_exception.side_effect = Exception(
                'Fake exception to get out of the loop')
            scan_ports.side_effect = [reply2, reply3]
            process_network_ports.side_effect = [
                False, Exception('Fake exception to get out of the loop')]

            q_agent = ovs_neutron_agent.OVSNeutronAgent(self.INT_BRIDGE,
                                                        self.TUN_BRIDGE,
                                                        '10.0.0.1',
                                                        self.NET_MAPPING,
                                                        'sudo', 2, ['gre'],
                                                        self.VETH_MTU)

            # Hack to test loop
            # We start method and expect it will raise after 2nd loop
            # If something goes wrong, assert_has_calls below will catch it
            try:
                q_agent.daemon_loop()
            except Exception:
                pass

        # FIXME(salv-orlando): There should not be assertions on log messages
        log_exception.assert_called_once_with(
            "Error while processing VIF ports")
        scan_ports.assert_has_calls([
            mock.call(set(), set()),
            mock.call(set(['tap0']), set())
        ])
        process_network_ports.assert_has_calls([
            mock.call({'current': set(['tap0']),
                       'removed': set([]),
                       'added': set(['tap2'])}, False),
            mock.call({'current': set(['tap2']),
                       'removed': set(['tap0']),
                       'added': set([])}, False)
        ])
        self._verify_mock_calls()


class TunnelTestWithMTU(TunnelTest):

    def setUp(self):
        super(TunnelTestWithMTU, self).setUp()
        self.VETH_MTU = 1500
        self.inta_expected.append(mock.call.link.set_mtu(self.VETH_MTU))
        self.intb_expected.append(mock.call.link.set_mtu(self.VETH_MTU))
