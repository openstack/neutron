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

import collections
import time
from unittest import mock

from neutron_lib import constants as n_const
from neutron_lib.plugins.ml2 import ovs_constants
from oslo_config import cfg
from oslo_log import log

from neutron.agent.common import ip_lib
from neutron.agent.common import ovs_lib
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import test_vlanmanager


Switch = collections.namedtuple('Switch', ['br_name'])

# Useful global dummy variables.
NET_UUID = '3faeebfe-5d37-11e1-a64b-000c29d5f0a7'
LS_ID = 420
LV_ID = 42
LV_IDS = [42, 43]
VIF_ID = '404deaec-5d37-11e1-a64b-000c29d5f0a8'
VIF_MAC = '3c:09:24:1e:78:23'
OFPORT_NUM = 1
VIF_PORT = ovs_lib.VifPort('port', OFPORT_NUM, VIF_ID, VIF_MAC,
                           Switch(br_name='br_name'))
VIF_PORTS = {VIF_ID: VIF_PORT}
FIXED_IPS = [{'subnet_id': 'my-subnet-uuid',
              'ip_address': '1.1.1.1'}]
VM_DEVICE_OWNER = n_const.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'

TUN_OFPORTS = {n_const.TYPE_GRE: {'ip1': '11', 'ip2': '12'}}

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
    def setUp(self):
        super(TunnelTest, self).setUp()
        self.useFixture(test_vlanmanager.LocalVlanManagerFixture())
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        mock.patch(
            'neutron.api.rpc.handlers.resources_rpc.ResourcesPullRpcApi'
        ).start()
        self.addCleanup(conn_patcher.stop)
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        cfg.CONF.set_override('explicitly_egress_direct', True, 'AGENT')

        self.INT_BRIDGE = 'integration_bridge'
        self.TUN_BRIDGE = 'tunnel_bridge'
        self.MAP_TUN_BRIDGE = 'tun_br_map'
        self.AUX_BRIDGE = 'ancillary_bridge'
        self.NET_MAPPING = ['net1:%s' % self.MAP_TUN_BRIDGE]
        self.INT_OFPORT = 11111
        self.TUN_OFPORT = 22222
        self.MAP_TUN_INT_OFPORT = 33333
        self.MAP_TUN_PHY_OFPORT = 44444

        self.LVM_DATA = (
            LV_ID, 'gre', None, LS_ID, VIF_PORTS)
        self.LVM_FLAT_DATA = (
            LV_ID, 'flat', 'net1', LS_ID, VIF_PORTS)
        self.LVM_VLAN_DATA = (
            LV_ID, 'vlan', 'net1', LS_ID, VIF_PORTS)

        self.inta = mock.Mock()
        self.intb = mock.Mock()

        mock.patch.object(ovs_lib.BaseOVS, 'config',
                          new_callable=mock.PropertyMock,
                          return_value={}).start()

        mock.patch('neutron.agent.ovsdb.impl_idl._connection').start()
        self.ovs_bridges = {
            self.INT_BRIDGE: mock.create_autospec(
                self.br_int_cls('br-int')),
            self.TUN_BRIDGE: mock.create_autospec(
                self.br_tun_cls('br-tun')),
            self.MAP_TUN_BRIDGE: mock.create_autospec(
                self.br_phys_cls('br-phys')),
            self.AUX_BRIDGE: mock.create_autospec(
                ovs_lib.OVSBridge('br-aux')),
        }
        self.ovs_int_ofports = {
            'patch-tun': self.TUN_OFPORT,
            'int-%s' % self.MAP_TUN_BRIDGE: self.MAP_TUN_INT_OFPORT
        }

        mock.patch('neutron.agent.rpc.PluginReportStateAPI.'
                   'has_alive_neutron_server').start()

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
        self.mock_aux_bridge_cls = mock.patch(
            'neutron.agent.common.ovs_lib.OVSBridge',
            autospec=True).start()
        self.mock_aux_bridge_cls.side_effect = lookup_br

        self.mock_int_bridge = self.ovs_bridges[self.INT_BRIDGE]
        self.mock_int_bridge.add_port.return_value = self.MAP_TUN_INT_OFPORT
        self.mock_int_bridge.add_patch_port.side_effect = (
            lambda tap, peer: self.ovs_int_ofports[tap])
        self.mock_int_bridge.port_exists.return_value = False
        self.mock_int_bridge.get_vif_ports.return_value = []
        self.mock_int_bridge.get_ports_attributes.return_value = []
        self.mock_int_bridge.db_get_val.return_value = {}

        self.mock_map_tun_bridge = self.ovs_bridges[self.MAP_TUN_BRIDGE]
        self.mock_map_tun_bridge.br_name = self.MAP_TUN_BRIDGE
        self.mock_map_tun_bridge.add_port.return_value = (
            self.MAP_TUN_PHY_OFPORT)
        self.mock_map_tun_bridge.add_patch_port.return_value = (
            self.MAP_TUN_PHY_OFPORT)
        self.mock_map_tun_bridge.port_exists.return_value = False

        self.mock_tun_bridge = self.ovs_bridges[self.TUN_BRIDGE]
        self.mock_tun_bridge.add_port.return_value = self.INT_OFPORT
        self.mock_tun_bridge.add_patch_port.return_value = self.INT_OFPORT

        self.ipdevice = mock.patch.object(ip_lib, 'IPDevice').start()

        self.ipwrapper = mock.patch.object(ip_lib, 'IPWrapper').start()
        add_veth = self.ipwrapper.return_value.add_veth
        add_veth.return_value = [self.inta, self.intb]

        self.get_bridges = mock.patch.object(ovs_lib.BaseOVS,
                                             'get_bridges').start()
        self.get_bridges.return_value = [self.INT_BRIDGE,
                                         self.TUN_BRIDGE,
                                         self.MAP_TUN_BRIDGE,
                                         self.AUX_BRIDGE]
        self.get_bridge_external_bridge_id = mock.patch.object(
            ovs_lib.BaseOVS,
            'get_bridge_external_bridge_id').start()
        self.get_bridge_external_bridge_id.side_effect = (
            lambda bridge, log_errors: bridge if bridge in self.ovs_bridges
            else None)

        self.execute = mock.patch('neutron.agent.common.utils.execute').start()
        self.mock_check_bridge_datapath_id = mock.patch.object(
            self.mod_agent.OVSNeutronAgent,
            '_check_bridge_datapath_id').start()
        self._define_expected_calls()

    def _define_expected_calls(
            self, arp_responder=False, igmp_snooping=False):
        self.mock_int_bridge_cls_expected = [
            mock.call(self.INT_BRIDGE,
                      datapath_type=mock.ANY),
        ]
        self.mock_phys_bridge_cls_expected = [
            mock.call(self.MAP_TUN_BRIDGE,
                      datapath_type=mock.ANY),
        ]
        self.mock_tun_bridge_cls_expected = [
            mock.call(self.TUN_BRIDGE,
                      datapath_type=mock.ANY),
        ]

        self.mock_int_bridge = self.ovs_bridges[self.INT_BRIDGE]
        self.mock_int_bridge_expected = [
            mock.call.create(),
            mock.call.set_secure_mode(),
            mock.call.setup_controllers(mock.ANY),
            mock.call.set_igmp_snooping_state(igmp_snooping),
            mock.call.setup_default_table(enable_openflow_dhcp=False,
                                          enable_dhcpv6=False),
        ]

        self.mock_map_tun_bridge_expected = [
            mock.call.create(),
            mock.call.set_secure_mode(),
            mock.call.setup_controllers(mock.ANY),
            mock.call.setup_default_table(),
            mock.call.port_exists('phy-%s' % self.MAP_TUN_BRIDGE),
            mock.call.add_patch_port('phy-%s' % self.MAP_TUN_BRIDGE,
                                     ovs_constants.NONEXISTENT_PEER),
        ]
        self.mock_int_bridge_expected += [
            mock.call.db_get_val('Interface', 'int-%s' % self.MAP_TUN_BRIDGE,
                                 'type', log_errors=False),
            mock.call.port_exists('int-%s' % self.MAP_TUN_BRIDGE),
            mock.call.add_patch_port('int-%s' % self.MAP_TUN_BRIDGE,
                                     ovs_constants.NONEXISTENT_PEER),
            mock.call.set_igmp_snooping_flood('int-%s' % self.MAP_TUN_BRIDGE),
        ]

        self.mock_int_bridge_expected += [
            mock.call.drop_port(in_port=self.MAP_TUN_INT_OFPORT),
            mock.call.set_db_attribute(
                'Interface', 'int-%s' % self.MAP_TUN_BRIDGE,
                'options', {'peer': 'phy-%s' % self.MAP_TUN_BRIDGE}),
        ]
        self.mock_map_tun_bridge_expected += [
            mock.call.drop_port(in_port=self.MAP_TUN_PHY_OFPORT),
            mock.call.set_db_attribute(
                'Interface', 'phy-%s' % self.MAP_TUN_BRIDGE,
                'options', {'peer': 'int-%s' % self.MAP_TUN_BRIDGE}),
        ]

        self.mock_aux_bridge = self.ovs_bridges[self.AUX_BRIDGE]
        self.mock_aux_bridge_expected = [
        ]

        self.mock_tun_bridge_expected = [
            mock.call.create(secure_mode=True),
            mock.call.setup_controllers(mock.ANY),
            mock.call.port_exists('patch-int'),
            mock.ANY,
            mock.call.add_patch_port('patch-int', 'patch-tun'),
        ]
        self.mock_int_bridge_expected += [
            mock.call.port_exists('patch-tun'),
            mock.call.add_patch_port('patch-tun', 'patch-int'),
            mock.call.set_igmp_snooping_flood('patch-tun'),
        ]
        self.mock_int_bridge_expected += [
            mock.call.get_vif_ports((ovs_lib.INVALID_OFPORT,
                                     ovs_lib.UNASSIGNED_OFPORT)),
            mock.call.get_ports_attributes(
                'Port', columns=['name', 'other_config', 'tag'], ports=[])
        ]

        self.mock_tun_bridge_expected += [
            # NOTE: Parameters passed to setup_default_table() method are named
            # in the production code. That's why we can't use keyword parameter
            # here. The last parameter passed below is dvr_enabled set to False
            mock.call.setup_default_table(
                self.INT_OFPORT, arp_responder, False),
        ]

        self.ipdevice_expected = []
        self.ipwrapper_expected = [mock.call()]

        self.get_bridges_expected = [mock.call(), mock.call()]

        self.inta_expected = []
        self.intb_expected = []
        self.execute_expected = []

        self.mock_int_bridge_expected += [
            mock.call.install_goto(
                dest_table_id=ovs_constants.LOCAL_MAC_DIRECT,
                in_port=self.MAP_TUN_INT_OFPORT,
                priority=4, table_id=ovs_constants.TRANSIENT_TABLE),
            mock.call.install_goto(
                dest_table_id=ovs_constants.LOCAL_MAC_DIRECT,
                in_port=self.TUN_OFPORT,
                priority=4, table_id=ovs_constants.TRANSIENT_TABLE),
            mock.call.install_goto(
                dest_table_id=ovs_constants.TRANSIENT_EGRESS_TABLE,
                table_id=ovs_constants.LOCAL_MAC_DIRECT),
        ]

    def _build_agent(self, **config_opts_agent):
        """Configure and initialize OVS agent.

        :param config_opts_agent: a dict with options to override the
               default values for the AGENT group.
        """
        bridge_classes = {
            'br_int': self.mock_int_bridge_cls,
            'br_phys': self.mock_phys_bridge_cls,
            'br_tun': self.mock_tun_bridge_cls,
        }
        cfg.CONF.set_override('integration_bridge', self.INT_BRIDGE, 'OVS')
        cfg.CONF.set_override('tunnel_bridge', self.TUN_BRIDGE, 'OVS')
        cfg.CONF.set_override('local_ip', '10.0.0.1', 'OVS')
        cfg.CONF.set_override('bridge_mappings', self.NET_MAPPING, 'OVS')
        cfg.CONF.set_override('polling_interval', 2, 'AGENT')
        cfg.CONF.set_override('tunnel_types', ['gre'], 'AGENT')
        cfg.CONF.set_override('minimize_polling', False, 'AGENT')
        cfg.CONF.set_override('enable_ipv6', False, 'DHCP')

        for k, v in config_opts_agent.items():
            cfg.CONF.set_override(k, v, 'AGENT')

        ext_mgr = mock.Mock()
        ext_mgr.names = mock.Mock(return_value=[])
        agent = self.mod_agent.OVSNeutronAgent(
            bridge_classes, ext_mgr, cfg.CONF)
        mock.patch.object(agent.ovs.ovsdb, 'idl_monitor').start()
        return agent

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
        self._verify_mock_call(self.mock_aux_bridge,
                               self.mock_aux_bridge_expected)
        self._verify_mock_call(self.ipdevice, self.ipdevice_expected)
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
        self._define_expected_calls(arp_responder=True)
        self._verify_mock_calls()

    def test_construct_with_igmp_snooping(self):
        cfg.CONF.set_override('igmp_snooping_enable', True, 'OVS')
        self._build_agent()
        self._define_expected_calls(igmp_snooping=True)
        self._verify_mock_calls()

    def test_construct_without_arp_responder(self):
        self._build_agent(l2_population=False, arp_responder=True)
        self._verify_mock_calls()

    def test_construct_vxlan(self):
        self._build_agent(tunnel_types=['vxlan'])
        self._verify_mock_calls()

    def test_provision_local_vlan(self):
        ofports = list(TUN_OFPORTS[n_const.TYPE_GRE].values())
        self.mock_tun_bridge_expected += [
            mock.call.install_flood_to_tun(LV_ID, LS_ID, ofports),
            mock.call.provision_local_vlan(
                network_type=n_const.TYPE_GRE,
                lvid=LV_ID,
                segmentation_id=LS_ID),
        ]

        a = self._build_agent()
        a.available_local_vlans = set([LV_ID])
        a.tun_br_ofports = TUN_OFPORTS
        a.provision_local_vlan(NET_UUID, n_const.TYPE_GRE, None, LS_ID)
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
        a.provision_local_vlan(NET_UUID, n_const.TYPE_FLAT, 'net1', LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_flat_fail(self):
        a = self._build_agent()
        a.provision_local_vlan(NET_UUID, n_const.TYPE_FLAT, 'net2', LS_ID)
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
        a.provision_local_vlan(NET_UUID, n_const.TYPE_VLAN, 'net1', LS_ID)
        self._verify_mock_calls()

    def test_provision_local_vlan_vlan_fail(self):
        a = self._build_agent()
        a.provision_local_vlan(NET_UUID, n_const.TYPE_VLAN, 'net2', LS_ID)
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
        a.vlan_manager.add(NET_UUID, *self.LVM_DATA)
        a.reclaim_local_vlan(NET_UUID, LS_ID)
        self.assertIn(self.LVM_DATA[0], a.available_local_vlans)
        self._verify_mock_calls()

    def test_reclaim_local_vlan_flat(self):
        self.mock_map_tun_bridge_expected.append(
            mock.call.reclaim_local_vlan(
                port=self.MAP_TUN_PHY_OFPORT,
                lvid=self.LVM_FLAT_DATA[0]))
        self.mock_int_bridge_expected.append(
            mock.call.reclaim_local_vlan(
                port=self.INT_OFPORT,
                segmentation_id=None))
        a = self._build_agent()
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_PHY_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT

        a.available_local_vlans = set()
        a.vlan_manager.add(NET_UUID, *self.LVM_FLAT_DATA)
        a.reclaim_local_vlan(NET_UUID, LS_ID)
        self.assertIn(self.LVM_FLAT_DATA[0], a.available_local_vlans)
        self._verify_mock_calls()

    def test_reclaim_local_vlan_vlan(self):
        self.mock_map_tun_bridge_expected.append(
            mock.call.reclaim_local_vlan(
                port=self.MAP_TUN_PHY_OFPORT,
                lvid=self.LVM_VLAN_DATA[0]))
        self.mock_int_bridge_expected.append(
            mock.call.reclaim_local_vlan(
                port=self.INT_OFPORT,
                segmentation_id=LS_ID))
        a = self._build_agent()
        a.phys_brs['net1'] = self.mock_map_tun_bridge
        a.phys_ofports['net1'] = self.MAP_TUN_PHY_OFPORT
        a.int_ofports['net1'] = self.INT_OFPORT

        a.available_local_vlans = set()
        a.vlan_manager.add(NET_UUID, *self.LVM_VLAN_DATA)
        a.reclaim_local_vlan(NET_UUID, LS_ID)
        self.assertIn(self.LVM_VLAN_DATA[0], a.available_local_vlans)
        self._verify_mock_calls()

    def test_port_bound(self):
        vlan_mapping = {'segmentation_id': str(LS_ID),
                        'physical_network': 'None',
                        'net_uuid': NET_UUID,
                        'network_type': 'gre',
                        'tag': str(LV_ID)}
        self.mock_int_bridge_expected += [
            mock.call.db_get_val('Port', 'port', 'other_config'),
            mock.call.set_db_attribute('Port', VIF_PORT.port_name,
                                       'other_config',
                                       vlan_mapping)]

        a = self._build_agent()
        a.vlan_manager.add(NET_UUID, *self.LVM_DATA)
        a.local_dvr_map = {}
        self.ovs_bridges[self.INT_BRIDGE].db_get_val.return_value = {}
        with mock.patch.object(a, "_set_port_vlan") as set_vlan:
            a.port_bound(VIF_PORT, NET_UUID, 'gre', None, LS_ID,
                         FIXED_IPS, VM_DEVICE_OWNER, False)
            self._verify_mock_calls()
            set_vlan.assert_called_once_with(VIF_PORT, LV_ID)

    def test_port_unbound(self):
        with mock.patch.object(self.mod_agent.OVSNeutronAgent,
                               'reclaim_local_vlan') as reclaim_local_vlan:
            a = self._build_agent()
            a.vlan_manager.add(NET_UUID, *self.LVM_DATA)
            a.port_unbound(VIF_ID, NET_UUID)

        reclaim_local_vlan.assert_called_once_with(NET_UUID, LS_ID)
        self._verify_mock_calls()

    def test_port_dead(self):
        self.mock_int_bridge_expected += [
            mock.call.db_get_val('Port', VIF_PORT.port_name, 'tag',
                                 log_errors=True),
            mock.call.set_db_attribute(
                'Port', VIF_PORT.port_name,
                'tag', ovs_constants.DEAD_VLAN_TAG,
                log_errors=True),
            mock.call.drop_port(in_port=VIF_PORT.ofport),
        ]

        a = self._build_agent()
        a.available_local_vlans = set([LV_ID])
        a.vlan_manager.add(NET_UUID, *self.LVM_DATA)
        self.ovs_bridges[self.INT_BRIDGE].db_get_val.return_value = mock.Mock()
        a.port_dead(VIF_PORT)
        self._verify_mock_calls()

    def test_tunnel_update(self):
        tunnel_port = '9999'
        self.mock_tun_bridge.add_tunnel_port.return_value = tunnel_port
        self.mock_tun_bridge_expected += [
            mock.call.add_tunnel_port('gre-0a000a01', '10.0.10.1', '10.0.0.1',
                                      'gre', 4789, True, False, None),
            mock.call.setup_tunnel_port('gre', tunnel_port),
        ]

        a = self._build_agent()
        a.tunnel_update(
            mock.sentinel.ctx, tunnel_ip='10.0.10.1',
            tunnel_type=n_const.TYPE_GRE)
        self._verify_mock_calls()

    def test_tunnel_update_self(self):
        a = self._build_agent()
        a.tunnel_update(
            mock.sentinel.ctx, tunnel_ip='10.0.0.1')
        self._verify_mock_calls()

    def test_daemon_loop(self):
        reply_ge_1 = {'added': [{'name': 'tap0', 'ofport': 3,
                                 'external_ids': {
                                     'attached-mac': 'test_mac'}}],
                      'removed': []}

        reply_ge_2 = {'added': [],
                      'removed': [{'name': 'tap0', 'ofport': 3,
                                   'external_ids': {
                                       'attached-mac': 'test_mac'}}]}

        reply_pe_1 = {'current': set(['tap0']),
                      'added': set(['tap0']),
                      'removed': set([])}

        reply_pe_2 = {'current': set([]),
                      'added': set([]),
                      'removed': set(['tap0'])}

        reply_ancillary = {'current': set([]),
                           'added': set([]),
                           'removed': set([])}

        self.mock_int_bridge_expected += [
            mock.call.check_canary_table(),
            mock.call.deferred(full_ordered=True, use_bundle=True),
            mock.call.deferred().__enter__(),
            mock.call.deferred().__exit__(None, None, None),
            mock.call.cleanup_flows(),
            mock.call.check_canary_table(),
            mock.call.deferred(full_ordered=True, use_bundle=True),
            mock.call.deferred().__enter__(),
            mock.call.deferred().__exit__(None, None, None),
        ]
        self.mock_map_tun_bridge_expected += [
            mock.call.cleanup_flows(),
        ]
        self.mock_tun_bridge_expected += [
            mock.call.cleanup_flows()
        ]
        # No cleanup is expected on ancillary bridge

        self.ovs_bridges[self.INT_BRIDGE].check_canary_table.return_value = \
            ovs_constants.OVS_NORMAL
        with mock.patch.object(log.KeywordArgumentAdapter,
                               'exception') as log_exception,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'process_ports_events') as process_p_events,\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    'process_network_ports') as process_network_ports,\
                mock.patch.object(self.mod_agent.OVSNeutronAgent,
                                  'tunnel_sync'),\
                mock.patch.object(time, 'sleep'),\
                mock.patch.object(
                    self.mod_agent.OVSNeutronAgent,
                    'update_stale_ofport_rules') as update_stale:
            log_exception.side_effect = Exception(
                'Fake exception to get out of the loop')
            update_stale.return_value = []
            devices_not_ready = set()
            process_p_events.side_effect = [
                (reply_pe_1, reply_ancillary, devices_not_ready),
                (reply_pe_2, reply_ancillary, devices_not_ready)]
            interface_polling = mock.Mock()
            interface_polling.get_events.side_effect = [reply_ge_1, reply_ge_2]
            failed_devices = {'removed': set([]), 'added': set([])}
            failed_ancillary_devices = {'removed': set([]), 'added': set([])}
            process_network_ports.side_effect = [
                failed_devices,
                Exception('Fake exception to get out of the loop')]

            n_agent = self._build_agent()

            # Hack to test loop
            # We start method and expect it will raise after 2nd loop
            # If something goes wrong, assert_has_calls below will catch it
            try:
                n_agent.rpc_loop(interface_polling)
            except Exception:
                pass

            # FIXME(salv-orlando): There should not be assertions on log
            # messages
            log_exception.assert_called_once_with(
                "Error while processing VIF ports")
            process_p_events.assert_has_calls([
                mock.call(reply_ge_1, set(), set(), devices_not_ready,
                          failed_devices, failed_ancillary_devices, set()),
                mock.call(reply_ge_2, set(['tap0']), set(), devices_not_ready,
                          failed_devices, failed_ancillary_devices,
                          set())
            ])
            process_network_ports.assert_has_calls([
                mock.call({'current': set(['tap0']),
                           'removed': set([]),
                           'added': set(['tap0'])}, False),
            ])

            self.assertTrue(update_stale.called)
            self._verify_mock_calls()


class TunnelTestOSKen(TunnelTest, ovs_test_base.OVSOSKenTestBase):
    pass
