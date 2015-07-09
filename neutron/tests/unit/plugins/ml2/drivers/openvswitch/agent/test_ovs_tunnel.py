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

import time

import mock
from oslo_config import cfg
from oslo_log import log

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base


# Useful global dummy variables.
NET_UUID = '3faeebfe-5d37-11e1-a64b-000c29d5f0a7'
LS_ID = 420
LV_ID = 42
LV_IDS = [42, 43]
VIF_ID = '404deaec-5d37-11e1-a64b-000c29d5f0a8'
VIF_MAC = '3c:09:24:1e:78:23'
OFPORT_NUM = 1
VIF_PORT = ovs_lib.VifPort('port', OFPORT_NUM,
                           VIF_ID, VIF_MAC, 'switch')
VIF_PORTS = {VIF_ID: VIF_PORT}
FIXED_IPS = [{'subnet_id': 'my-subnet-uuid',
              'ip_address': '1.1.1.1'}]
VM_DEVICE_OWNER = "compute:None"

TUN_OFPORTS = {p_const.TYPE_GRE: {'ip1': '11', 'ip2': '12'}}

BCAST_MAC = "01:00:00:00:00:00/01:00:00:00:00:00"
UCAST_MAC = "00:00:00:00:00:00/01:00:00:00:00:00"


class DummyPort(object):
    def __init__(self, interface_id):
        self.interface_id = interface_id


class DummyVlanBinding(object):
    def __init__(self, network_id, vlan_id):
        self.network_id = network_id
        self.vlan_id = vlan_id


class TunnelTest(object):
    USE_VETH_INTERCONNECTION = False
    VETH_MTU = None

    def setUp(self):
        super(TunnelTest, self).setUp()
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_override('report_interval', 0, 'AGENT')

        self.INT_BRIDGE = 'integration_bridge'
        self.TUN_BRIDGE = 'tunnel_bridge'
        self.MAP_TUN_BRIDGE = 'tun_br_map'
        self.NET_MAPPING = {'net1': self.MAP_TUN_BRIDGE}
        self.INT_OFPORT = 11111
        self.TUN_OFPORT = 22222
        self.MAP_TUN_INT_OFPORT = 33333
        self.MAP_TUN_PHY_OFPORT = 44444

        self.LVM = self.mod_agent.LocalVLANMapping(
            LV_ID, 'gre', None, LS_ID, VIF_PORTS)
        self.LVM_FLAT = self.mod_agent.LocalVLANMapping(
            LV_ID, 'flat', 'net1', LS_ID, VIF_PORTS)
        self.LVM_VLAN = self.mod_agent.LocalVLANMapping(
            LV_ID, 'vlan', 'net1', LS_ID, VIF_PORTS)

        self.inta = mock.Mock()
        self.intb = mock.Mock()

        self.ovs_bridges = {
            self.INT_BRIDGE: mock.create_autospec(
                self.br_int_cls('br-int')),
            self.TUN_BRIDGE: mock.create_autospec(
                self.br_tun_cls('br-tun')),
            self.MAP_TUN_BRIDGE: mock.create_autospec(
                self.br_phys_cls('br-phys')),
        }
        self.ovs_int_ofports = {
            'patch-tun': self.TUN_OFPORT,
            'int-%s' % self.MAP_TUN_BRIDGE: self.MAP_TUN_INT_OFPORT
        }

        def lookup_br(br_name, *args, **kwargs):
            return self.ovs_bridges[br_name]

        self.mock_int_bridge_cls = mock.patch(self._BR_INT_CLASS,
                                              autospec=True).start()
        self.mock_int_bridge_cls.side_effect = lookup_br
        self.mock_phys_bridge_cls = mock.patch(self._BR_PHYS_CLASS,
                                               autospec=True).start()
        self.mock_phys_bridge_cls.side_effect = lookup_br
        self.mock_tun_bridge_cls = mock.patch(self._BR_TUN_CLASS,
                                              autospec=True).start()
        self.mock_tun_bridge_cls.side_effect = lookup_br

        self.mock_int_bridge = self.ovs_bridges[self.INT_BRIDGE]
        self.mock_int_bridge.add_port.return_value = self.MAP_TUN_INT_OFPORT
        self.mock_int_bridge.add_patch_port.side_effect = (
            lambda tap, peer: self.ovs_int_ofports[tap])
        self.mock_int_bridge.get_vif_ports.return_value = []
        self.mock_int_bridge.db_list.return_value = []
        self.mock_int_bridge.db_get_val.return_value = {}

        self.mock_map_tun_bridge = self.ovs_bridges[self.MAP_TUN_BRIDGE]
        self.mock_map_tun_bridge.br_name = self.MAP_TUN_BRIDGE
        self.mock_map_tun_bridge.add_port.return_value = (
            self.MAP_TUN_PHY_OFPORT)
        self.mock_map_tun_bridge.add_patch_port.return_value = (
            self.MAP_TUN_PHY_OFPORT)

        self.mock_tun_bridge = self.ovs_bridges[self.TUN_BRIDGE]
        self.mock_tun_bridge.add_port.return_value = self.INT_OFPORT
        self.mock_tun_bridge.add_patch_port.return_value = self.INT_OFPORT

        self.device_exists = mock.patch.object(ip_lib, 'device_exists').start()
        self.device_exists.return_value = True

        self.ipdevice = mock.patch.object(ip_lib, 'IPDevice').start()

        self.ipwrapper = mock.patch.object(ip_lib, 'IPWrapper').start()
        add_veth = self.ipwrapper.return_value.add_veth
        add_veth.return_value = [self.inta, self.intb]

        self.get_bridges = mock.patch.object(ovs_lib.BaseOVS,
                                             'get_bridges').start()
        self.get_bridges.return_value = [self.INT_BRIDGE,
                                         self.TUN_BRIDGE,
                                         self.MAP_TUN_BRIDGE]

        self.execute = mock.patch('neutron.agent.common.utils.execute').start()

        self._define_expected_calls()

    def _define_expected_calls(self, arp_responder=False):
        self.mock_int_bridge_cls_expected = [
            mock.call(self.INT_BRIDGE),
        ]
        self.mock_phys_bridge_cls_expected = [
            mock.call(self.MAP_TUN_BRIDGE),
        ]
        self.mock_tun_bridge_cls_expected = [
            mock.call(self.TUN_BRIDGE),
        ]

        self.mock_int_bridge = self.ovs_bridges[self.INT_BRIDGE]
        self.mock_int_bridge_expected = [
            mock.call.create(),
            mock.call.set_secure_mode(),
            mock.call.setup_controllers(mock.ANY),
            mock.call.delete_port('patch-tun'),
            mock.call.setup_default_table(),
        ]

        self.mock_map_tun_bridge_expected = [
            mock.call.setup_controllers(mock.ANY),
            mock.call.setup_default_table(),
            mock.call.delete_port('phy-%s' % self.MAP_TUN_BRIDGE),
            mock.call.add_patch_port('phy-%s' % self.MAP_TUN_BRIDGE,
                                     constants.NONEXISTENT_PEER), ]
        self.mock_int_bridge_expected += [
            mock.call.delete_port('int-%s' % self.MAP_TUN_BRIDGE),
            mock.call.add_patch_port('int-%s' % self.MAP_TUN_BRIDGE,
                                     constants.NONEXISTENT_PEER),
        ]

        self.mock_int_bridge_expected += [
            mock.call.drop_port(in_port=self.MAP_TUN_INT_OFPORT),
            mock.call.set_db_attribute(
                'Interface', 'int-%s' % self.MAP_TUN_BRIDGE,
                'options:peer', 'phy-%s' % self.MAP_TUN_BRIDGE),
        ]
        self.mock_map_tun_bridge_expected += [
            mock.call.drop_port(in_port=self.MAP_TUN_PHY_OFPORT),
            mock.call.set_db_attribute(
                'Interface', 'phy-%s' % self.MAP_TUN_BRIDGE,
                'options:peer', 'int-%s' % self.MAP_TUN_BRIDGE),
        ]

        self.mock_tun_bridge_expected = [
            mock.call.reset_bridge(secure_mode=True),
            mock.call.setup_controllers(mock.ANY),
            mock.call.add_patch_port('patch-int', 'patch-tun'),
        ]
        self.mock_int_bridge_expected += [
            mock.call.add_patch_port('patch-tun', 'patch-int'),
        ]
        self.mock_int_bridge_expected += [
            mock.call.get_vif_ports(),
            mock.call.db_list('Port', columns=['name', 'other_config', 'tag'])
        ]

        self.mock_tun_bridge_expected += [
            mock.call.delete_flows(),
            mock.call.setup_default_table(self.INT_OFPORT, arp_responder),
        ]

        self.device_exists_expected = []

        self.ipdevice_expected = []
        self.ipwrapper_expected = [mock.call()]

        self.get_bridges_expected = [mock.call(), mock.call()]

        self.inta_expected = []
        self.intb_expected = []
        self.execute_expected = []

    def _build_agent(self, **kwargs):
        bridge_classes = {
            'br_int': self.mock_int_bridge_cls,
            'br_phys': self.mock_phys_bridge_cls,
            'br_tun': self.mock_tun_bridge_cls,
        }
        kwargs.setdefault('bridge_classes', bridge_classes)
        kwargs.setdefault('integ_br', self.INT_BRIDGE)
        kwargs.setdefault('tun_br', self.TUN_BRIDGE)
        kwargs.setdefault('local_ip', '10.0.0.1')
        kwargs.setdefault('bridge_mappings', self.NET_MAPPING)
        kwargs.setdefault('polling_interval', 2)
        kwargs.setdefault('tunnel_types', ['gre'])
        kwargs.setdefault('veth_mtu', self.VETH_MTU)
        kwargs.setdefault('use_veth_interconnection',
                          self.USE_VETH_INTERCONNECTION)
        return self.mod_agent.OVSNeutronAgent(**kwargs)

    def _verify_mock_call(self, mock_obj, expected):
        mock_obj.assert_has_calls(expected)
        self.assertEqual(expected, mock_obj.mock_calls)

    def _verify_mock_calls(self):
        self._verify_mock_call(self.mock_int_bridge_cls,
                               self.mock_int_bridge_cls_expected)
        self._verify_mock_call(self.mock_tun_bridge_cls,
                               self.mock_tun_bridge_cls_expected)
        self._verify_mock_call(self.mock_phys_bridge_cls,
                               self.mock_phys_bridge_cls_expected)
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
        agent = self._build_agent()
        self.assertEqual(agent.agent_id, 'ovs-agent-%s' % cfg.CONF.host)
        self._verify_mock_calls()

    # TODO(ethuleau): Initially, local ARP responder is be dependent to the
    #                 ML2 l2 population mechanism driver.
    #                 The next two tests use l2_pop flag to test ARP responder
    def test_construct_with_arp_responder(self):
        self._build_agent(l2_population=True, arp_responder=True)
        self._define_expected_calls(True)
        self._verify_mock_calls()

    def test_construct_without_arp_responder(self):
        self._build_agent(l2_population=False, arp_responder=True)
        self._verify_mock_calls()

    def test_construct_vxlan(self):
        self._build_agent(tunnel_types=['vxlan'])
        self._verify_mock_calls()

    def test_provision_local_vlan(self):
        ofports = TUN_OFPORTS[p_const.TYPE_GRE].values()
        self.mock_tun_bridge_expected += [
            mock.call.install_flood_to_tun(LV_ID, LS_ID, ofports),
            mock.call.provision_local_vlan(
                network_type=p_const.TYPE_GRE,
                lvid=LV_ID,
                segmentation_id=LS_ID),
        ]

        a = self._build_agent()
        a.available_local_vlans = set([LV_ID])
        a.tun_br_ofports = TUN_OFPORTS
        a.provision_local_vlan(NET_UUID, p_const.TYPE_GRE, None, LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_flat(self):
        self.mock_map_tun_bridge_expected.append(
            mock.call.provision_local_vlan(
                port=self.MAP_TUN_PHY_OFPORT,
                lvid=LV_ID,
                segmentation_id=None,
                distributed=False))
        self.mock_int_bridge_expected.append(
            mock.call.provision_local_vlan(
                port=self.INT_OFPORT,
                lvid=LV_ID,
                segmentation_id=None))

        a = self._build_agent()
        a.available_local_vlans = set([LV_ID])
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_PHY_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT
        a.provision_local_vlan(NET_UUID, p_const.TYPE_FLAT, 'net1', LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_flat_fail(self):
        a = self._build_agent()
        a.provision_local_vlan(NET_UUID, p_const.TYPE_FLAT, 'net2', LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_vlan(self):
        self.mock_map_tun_bridge_expected.append(
            mock.call.provision_local_vlan(
                port=self.MAP_TUN_PHY_OFPORT,
                lvid=LV_ID,
                segmentation_id=LS_ID,
                distributed=False))
        self.mock_int_bridge_expected.append(
            mock.call.provision_local_vlan(
                port=self.INT_OFPORT,
                lvid=LV_ID,
                segmentation_id=LS_ID))
        a = self._build_agent()
        a.available_local_vlans = set([LV_ID])
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_PHY_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT
        a.provision_local_vlan(NET_UUID, p_const.TYPE_VLAN, 'net1', LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_vlan_fail(self):
        a = self._build_agent()
        a.provision_local_vlan(NET_UUID, p_const.TYPE_VLAN, 'net2', LS_ID)
        self._verify_mock_calls()

    def test_reclaim_local_vlan(self):
        self.mock_tun_bridge_expected += [
            mock.call.reclaim_local_vlan(network_type='gre',
                                         segmentation_id=LS_ID),
            mock.call.delete_flood_to_tun(LV_ID),
            mock.call.delete_unicast_to_tun(LV_ID, None),
            mock.call.delete_arp_responder(LV_ID, None),
        ]

        a = self._build_agent()
        a.available_local_vlans = set()
        a.local_vlan_map[NET_UUID] = self.LVM
        a.reclaim_local_vlan(NET_UUID)
        self.assertIn(self.LVM.vlan, a.available_local_vlans)
        self._verify_mock_calls()

    def test_reclaim_local_vlan_flat(self):
        self.mock_map_tun_bridge_expected.append(
            mock.call.reclaim_local_vlan(
                port=self.MAP_TUN_PHY_OFPORT,
                lvid=self.LVM_FLAT.vlan))
        self.mock_int_bridge_expected.append(
            mock.call.reclaim_local_vlan(
                port=self.INT_OFPORT,
                segmentation_id=None))
        a = self._build_agent()
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_PHY_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT

        a.available_local_vlans = set()
        a.local_vlan_map[NET_UUID] = self.LVM_FLAT
        a.reclaim_local_vlan(NET_UUID)
        self.assertIn(self.LVM_FLAT.vlan, a.available_local_vlans)
        self._verify_mock_calls()

    def test_reclaim_local_vlan_vlan(self):
        self.mock_map_tun_bridge_expected.append(
            mock.call.reclaim_local_vlan(
                port=self.MAP_TUN_PHY_OFPORT,
                lvid=self.LVM_VLAN.vlan))
        self.mock_int_bridge_expected.append(
            mock.call.reclaim_local_vlan(
                port=self.INT_OFPORT,
                segmentation_id=LS_ID))
        a = self._build_agent()
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_PHY_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT

        a.available_local_vlans = set()
        a.local_vlan_map[NET_UUID] = self.LVM_VLAN
        a.reclaim_local_vlan(NET_UUID)
        self.assertIn(self.LVM_VLAN.vlan, a.available_local_vlans)
        self._verify_mock_calls()

    def test_port_bound(self):
        vlan_mapping = {'segmentation_id': LS_ID,
                        'physical_network': None,
                        'net_uuid': NET_UUID,
                        'network_type': 'gre'}
        self.mock_int_bridge_expected += [
            mock.call.db_get_val('Port', 'port', 'other_config'),
            mock.call.set_db_attribute('Port', VIF_PORT.port_name,
                                       'other_config',
                                       vlan_mapping)]

        a = self._build_agent()
        a.local_vlan_map[NET_UUID] = self.LVM
        a.local_dvr_map = {}
        self.ovs_bridges[self.INT_BRIDGE].db_get_val.return_value = {}
        a.port_bound(VIF_PORT, NET_UUID, 'gre', None, LS_ID,
                     FIXED_IPS, VM_DEVICE_OWNER, False)
        self._verify_mock_calls()

    def test_port_unbound(self):
        with mock.patch.object(self.mod_agent.OVSNeutronAgent,
                               'reclaim_local_vlan') as reclaim_local_vlan:
            a = self._build_agent()
            a.local_vlan_map[NET_UUID] = self.LVM
            a.port_unbound(VIF_ID, NET_UUID)

        reclaim_local_vlan.assert_called_once_with(NET_UUID)
        self._verify_mock_calls()

    def test_port_dead(self):
        self.mock_int_bridge_expected += [
            mock.call.db_get_val('Port', VIF_PORT.port_name, 'tag',
                                 log_errors=True),
            mock.call.set_db_attribute(
                'Port', VIF_PORT.port_name,
                'tag', self.mod_agent.DEAD_VLAN_TAG,
                log_errors=True),
            mock.call.drop_port(in_port=VIF_PORT.ofport),
        ]

        a = self._build_agent()
        a.available_local_vlans = set([LV_ID])
        a.local_vlan_map[NET_UUID] = self.LVM
        self.ovs_bridges[self.INT_BRIDGE].db_get_val.return_value = mock.Mock()
        a.port_dead(VIF_PORT)
        self._verify_mock_calls()

    def test_tunnel_update(self):
        tunnel_port = '9999'
        self.mock_tun_bridge.add_tunnel_port.return_value = tunnel_port
        self.mock_tun_bridge_expected += [
            mock.call.add_tunnel_port('gre-0a000a01', '10.0.10.1', '10.0.0.1',
                                      'gre', 4789, True),
            mock.call.setup_tunnel_port('gre', tunnel_port),
        ]

        a = self._build_agent()
        a.tunnel_update(
            mock.sentinel.ctx, tunnel_ip='10.0.10.1',
            tunnel_type=p_const.TYPE_GRE)
        self._verify_mock_calls()

    def test_tunnel_update_self(self):
        a = self._build_agent()
        a.tunnel_update(
            mock.sentinel.ctx, tunnel_ip='10.0.0.1')
        self._verify_mock_calls()

    def test_daemon_loop(self):
        reply2 = {'current': set(['tap0']),
                  'added': set(['tap2']),
                  'removed': set([])}

        reply3 = {'current': set(['tap2']),
                  'added': set([]),
                  'removed': set(['tap0'])}

        self.mock_int_bridge_expected += [
            mock.call.check_canary_table(),
            mock.call.check_canary_table()
        ]

        self.ovs_bridges[self.INT_BRIDGE].check_canary_table.return_value = \
            constants.OVS_NORMAL
        with mock.patch.object(log.KeywordArgumentAdapter,
                               'exception') as log_exception,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'scan_ports') as scan_ports,\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    'process_network_ports') as process_network_ports,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'tunnel_sync'),\
                mock.patch.object(time, 'sleep'),\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'update_stale_ofport_rules') as update_stale:
            log_exception.side_effect = Exception(
                'Fake exception to get out of the loop')
            scan_ports.side_effect = [reply2, reply3]
            process_network_ports.side_effect = [
                False, Exception('Fake exception to get out of the loop')]

            n_agent = self._build_agent()

            # Hack to test loop
            # We start method and expect it will raise after 2nd loop
            # If something goes wrong, assert_has_calls below will catch it
            try:
                n_agent.daemon_loop()
            except Exception:
                pass

            # FIXME(salv-orlando): There should not be assertions on log
            # messages
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
            self.assertTrue(update_stale.called)
            self._verify_mock_calls()


class TunnelTestOFCtl(TunnelTest, ovs_test_base.OVSOFCtlTestBase):
    pass


class TunnelTestUseVethInterco(TunnelTest):
    USE_VETH_INTERCONNECTION = True

    def _define_expected_calls(self, arp_responder=False):
        self.mock_int_bridge_cls_expected = [
            mock.call(self.INT_BRIDGE),
        ]
        self.mock_phys_bridge_cls_expected = [
            mock.call(self.MAP_TUN_BRIDGE),
        ]
        self.mock_tun_bridge_cls_expected = [
            mock.call(self.TUN_BRIDGE),
        ]

        self.mock_int_bridge_expected = [
            mock.call.create(),
            mock.call.set_secure_mode(),
            mock.call.setup_controllers(mock.ANY),
            mock.call.delete_port('patch-tun'),
            mock.call.setup_default_table(),
        ]

        self.mock_map_tun_bridge_expected = [
            mock.call.setup_controllers(mock.ANY),
            mock.call.setup_default_table(),
            mock.call.delete_port('phy-%s' % self.MAP_TUN_BRIDGE),
            mock.call.add_port(self.intb),
        ]
        self.mock_int_bridge_expected += [
            mock.call.delete_port('int-%s' % self.MAP_TUN_BRIDGE),
            mock.call.add_port(self.inta)
        ]

        self.mock_int_bridge_expected += [
            mock.call.drop_port(in_port=self.MAP_TUN_INT_OFPORT),
        ]
        self.mock_map_tun_bridge_expected += [
            mock.call.drop_port(in_port=self.MAP_TUN_PHY_OFPORT),
        ]

        self.mock_tun_bridge_expected = [
            mock.call.reset_bridge(secure_mode=True),
            mock.call.setup_controllers(mock.ANY),
            mock.call.add_patch_port('patch-int', 'patch-tun'),
        ]
        self.mock_int_bridge_expected += [
            mock.call.add_patch_port('patch-tun', 'patch-int')
        ]
        self.mock_int_bridge_expected += [
            mock.call.get_vif_ports(),
            mock.call.db_list('Port', columns=['name', 'other_config', 'tag'])
        ]
        self.mock_tun_bridge_expected += [
            mock.call.delete_flows(),
            mock.call.setup_default_table(self.INT_OFPORT, arp_responder),
        ]

        self.device_exists_expected = [
            mock.call('int-%s' % self.MAP_TUN_BRIDGE),
        ]

        self.ipdevice_expected = [
            mock.call('int-%s' % self.MAP_TUN_BRIDGE),
            mock.call().link.delete()
        ]
        self.ipwrapper_expected = [
            mock.call(),
            mock.call().add_veth('int-%s' % self.MAP_TUN_BRIDGE,
                                 'phy-%s' % self.MAP_TUN_BRIDGE)
        ]

        self.get_bridges_expected = [mock.call(), mock.call()]

        self.inta_expected = [mock.call.link.set_up()]
        self.intb_expected = [mock.call.link.set_up()]
        self.execute_expected = [mock.call(['udevadm', 'settle',
                                            '--timeout=10'])]


class TunnelTestUseVethIntercoOFCtl(TunnelTestUseVethInterco,
                                    ovs_test_base.OVSOFCtlTestBase):
    pass


class TunnelTestWithMTU(TunnelTestUseVethInterco):
    VETH_MTU = 1500

    def _define_expected_calls(self, arp_responder=False):
        super(TunnelTestWithMTU, self)._define_expected_calls(arp_responder)
        self.inta_expected.append(mock.call.link.set_mtu(self.VETH_MTU))
        self.intb_expected.append(mock.call.link.set_mtu(self.VETH_MTU))


class TunnelTestWithMTUOFCtl(TunnelTestWithMTU,
                             ovs_test_base.OVSOFCtlTestBase):
    pass
