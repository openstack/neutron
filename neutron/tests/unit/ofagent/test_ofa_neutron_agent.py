# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Based on test for openvswitch agent(test_ovs_neutron_agent.py).
#
# Copyright (c) 2012 OpenStack Foundation.
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
# @author: Fumihiko Kakuma, VA Linux Systems Japan K.K.
# @author: YAMAMOTO Takashi, VA Linux Systems Japan K.K.

import contextlib

import mock
import netaddr
from oslo.config import cfg
import testtools

from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import utils
from neutron.openstack.common import importutils
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.common import constants
from neutron.tests import base
from neutron.tests.unit.ofagent import fake_oflib


NOTIFIER = ('neutron.plugins.ml2.rpc.AgentNotifierApi')
OVS_LINUX_KERN_VERS_WITHOUT_VXLAN = "3.12.0"


class OFAAgentTestCase(base.BaseTestCase):

    _AGENT_NAME = 'neutron.plugins.ofagent.agent.ofa_neutron_agent'

    def setUp(self):
        super(OFAAgentTestCase, self).setUp()
        self.fake_oflib_of = fake_oflib.patch_fake_oflib_of().start()
        self.mod_agent = importutils.import_module(self._AGENT_NAME)
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        self.ryuapp = mock.Mock()
        cfg.CONF.register_cli_opts([
            cfg.StrOpt('ofp-listen-host', default='',
                       help='openflow listen host'),
            cfg.IntOpt('ofp-tcp-listen-port', default=6633,
                       help='openflow tcp listen port')
        ])
        cfg.CONF.set_override('root_helper', 'fake_helper', group='AGENT')


class CreateAgentConfigMap(OFAAgentTestCase):

    def test_create_agent_config_map_succeeds(self):
        self.assertTrue(self.mod_agent.create_agent_config_map(cfg.CONF))

    def test_create_agent_config_map_fails_for_invalid_tunnel_config(self):
        # An ip address is required for tunneling but there is no default,
        # verify this for both gre and vxlan tunnels.
        cfg.CONF.set_override('tunnel_types', [p_const.TYPE_GRE],
                              group='AGENT')
        with testtools.ExpectedException(ValueError):
            self.mod_agent.create_agent_config_map(cfg.CONF)
        cfg.CONF.set_override('tunnel_types', [p_const.TYPE_VXLAN],
                              group='AGENT')
        with testtools.ExpectedException(ValueError):
            self.mod_agent.create_agent_config_map(cfg.CONF)

    def test_create_agent_config_map_enable_tunneling(self):
        # Verify setting only enable_tunneling will default tunnel_type to GRE
        cfg.CONF.set_override('tunnel_types', None, group='AGENT')
        cfg.CONF.set_override('enable_tunneling', True, group='OVS')
        cfg.CONF.set_override('local_ip', '10.10.10.10', group='OVS')
        cfgmap = self.mod_agent.create_agent_config_map(cfg.CONF)
        self.assertEqual(cfgmap['tunnel_types'], [p_const.TYPE_GRE])

    def test_create_agent_config_map_fails_no_local_ip(self):
        # An ip address is required for tunneling but there is no default
        cfg.CONF.set_override('enable_tunneling', True, group='OVS')
        with testtools.ExpectedException(ValueError):
            self.mod_agent.create_agent_config_map(cfg.CONF)

    def test_create_agent_config_map_fails_for_invalid_tunnel_type(self):
        cfg.CONF.set_override('tunnel_types', ['foobar'], group='AGENT')
        with testtools.ExpectedException(ValueError):
            self.mod_agent.create_agent_config_map(cfg.CONF)

    def test_create_agent_config_map_multiple_tunnel_types(self):
        cfg.CONF.set_override('local_ip', '10.10.10.10', group='OVS')
        cfg.CONF.set_override('tunnel_types', [p_const.TYPE_GRE,
                              p_const.TYPE_VXLAN], group='AGENT')
        cfgmap = self.mod_agent.create_agent_config_map(cfg.CONF)
        self.assertEqual(cfgmap['tunnel_types'],
                         [p_const.TYPE_GRE, p_const.TYPE_VXLAN])


class TestOFANeutronAgentOVSBridge(OFAAgentTestCase):

    def setUp(self):
        super(TestOFANeutronAgentOVSBridge, self).setUp()
        self.br_name = 'bridge1'
        self.root_helper = 'fake_helper'
        self.ovs = self.mod_agent.OVSBridge(
            self.br_name, self.root_helper, self.ryuapp)

    def test_find_datapath_id(self):
        with mock.patch.object(self.ovs, 'get_datapath_id',
                               return_value='12345'):
            self.ovs.find_datapath_id()
        self.assertEqual(self.ovs.datapath_id, '12345')

    def _fake_get_datapath(self, app, datapath_id):
        if self.ovs.retry_count >= 2:
            datapath = mock.Mock()
            datapath.ofproto_parser = mock.Mock()
            return datapath
        self.ovs.retry_count += 1
        return None

    def test_get_datapath_normal(self):
        self.ovs.retry_count = 0
        with mock.patch.object(self.mod_agent.ryu_api, 'get_datapath',
                               new=self._fake_get_datapath):
            self.ovs.datapath_id = '0x64'
            self.ovs.get_datapath(retry_max=4)
        self.assertEqual(self.ovs.retry_count, 2)

    def test_get_datapath_retry_out_by_default_time(self):
        cfg.CONF.set_override('get_datapath_retry_times', 3, group='AGENT')
        with mock.patch.object(self.mod_agent.ryu_api, 'get_datapath',
                               return_value=None) as mock_get_datapath:
            with testtools.ExpectedException(SystemExit):
                self.ovs.datapath_id = '0x64'
                self.ovs.get_datapath(retry_max=3)
        self.assertEqual(mock_get_datapath.call_count, 3)

    def test_get_datapath_retry_out_by_specified_time(self):
        with mock.patch.object(self.mod_agent.ryu_api, 'get_datapath',
                               return_value=None) as mock_get_datapath:
            with testtools.ExpectedException(SystemExit):
                self.ovs.datapath_id = '0x64'
                self.ovs.get_datapath(retry_max=2)
        self.assertEqual(mock_get_datapath.call_count, 2)

    def test_setup_ofp_default_par(self):
        with contextlib.nested(
            mock.patch.object(self.ovs, 'set_protocols'),
            mock.patch.object(self.ovs, 'set_controller'),
            mock.patch.object(self.ovs, 'find_datapath_id'),
            mock.patch.object(self.ovs, 'get_datapath'),
        ) as (mock_set_protocols, mock_set_controller,
              mock_find_datapath_id, mock_get_datapath):
            self.ovs.setup_ofp()
        mock_set_protocols.assert_called_with('OpenFlow13')
        mock_set_controller.assert_called_with(['tcp:127.0.0.1:6633'])
        mock_get_datapath.assert_called_with(
            cfg.CONF.AGENT.get_datapath_retry_times)
        self.assertEqual(mock_find_datapath_id.call_count, 1)

    def test_setup_ofp_specify_par(self):
        controller_names = ['tcp:192.168.10.10:1234', 'tcp:172.17.16.20:5555']
        with contextlib.nested(
            mock.patch.object(self.ovs, 'set_protocols'),
            mock.patch.object(self.ovs, 'set_controller'),
            mock.patch.object(self.ovs, 'find_datapath_id'),
            mock.patch.object(self.ovs, 'get_datapath'),
        ) as (mock_set_protocols, mock_set_controller,
              mock_find_datapath_id, mock_get_datapath):
            self.ovs.setup_ofp(controller_names=controller_names,
                               protocols='OpenFlow133',
                               retry_max=11)
        mock_set_protocols.assert_called_with('OpenFlow133')
        mock_set_controller.assert_called_with(controller_names)
        mock_get_datapath.assert_called_with(11)
        self.assertEqual(mock_find_datapath_id.call_count, 1)

    def test_setup_ofp_with_except(self):
        with contextlib.nested(
            mock.patch.object(self.ovs, 'set_protocols',
                              side_effect=RuntimeError),
            mock.patch.object(self.ovs, 'set_controller'),
            mock.patch.object(self.ovs, 'find_datapath_id'),
            mock.patch.object(self.ovs, 'get_datapath'),
        ) as (mock_set_protocols, mock_set_controller,
              mock_find_datapath_id, mock_get_datapath):
            with testtools.ExpectedException(SystemExit):
                self.ovs.setup_ofp()


class TestOFANeutronAgent(OFAAgentTestCase):

    def setUp(self):
        super(TestOFANeutronAgent, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        # Avoid rpc initialization for unit tests
        cfg.CONF.set_override('rpc_backend',
                              'neutron.openstack.common.rpc.impl_fake')
        kwargs = self.mod_agent.create_agent_config_map(cfg.CONF)

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        def _mk_test_dp(name):
            ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
            ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
            dp = mock.Mock()
            dp.ofproto = ofp
            dp.ofproto_parser = ofpp
            dp.__repr__ = lambda _self: name
            return dp

        def _mk_test_br(name):
            dp = _mk_test_dp(name)
            br = mock.Mock()
            br.datapath = dp
            br.ofproto = dp.ofproto
            br.ofparser = dp.ofproto_parser
            return br

        with contextlib.nested(
            mock.patch.object(self.mod_agent.OFANeutronAgent,
                              'setup_integration_br',
                              return_value=mock.Mock()),
            mock.patch.object(self.mod_agent.OFANeutronAgent,
                              'setup_ancillary_bridges',
                              return_value=[]),
            mock.patch.object(self.mod_agent.OVSBridge,
                              'get_local_port_mac',
                              return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.openstack.common.loopingcall.'
                       'FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall)):
            self.agent = self.mod_agent.OFANeutronAgent(self.ryuapp, **kwargs)
            self.agent.tun_br = _mk_test_br('tun_br')
            self.datapath = mock.Mock()
            self.ofparser = mock.Mock()
            self.agent.phys_brs['phys-net1'] = _mk_test_br('phys_br1')
            self.agent.phys_ofports['phys-net1'] = 777
            self.agent.int_ofports['phys-net1'] = 666
            self.datapath.ofparser = self.ofparser
            self.ofparser.OFPMatch = mock.Mock()
            self.ofparser.OFPMatch.return_value = mock.Mock()
            self.ofparser.OFPFlowMod = mock.Mock()
            self.ofparser.OFPFlowMod.return_value = mock.Mock()
            self.agent.int_br.ofparser = self.ofparser
            self.agent.int_br.datapath = _mk_test_dp('int_br')

        self.agent.sg_agent = mock.Mock()

    def _mock_port_bound(self, ofport=None, new_local_vlan=None,
                         old_local_vlan=None):
        port = mock.Mock()
        port.ofport = ofport
        net_uuid = 'my-net-uuid'
        if old_local_vlan is not None:
            self.agent.local_vlan_map[net_uuid] = (
                self.mod_agent.LocalVLANMapping(
                    old_local_vlan, None, None, None))
        with contextlib.nested(
            mock.patch.object(self.mod_agent.OVSBridge,
                              'set_db_attribute', return_value=True),
            mock.patch.object(self.mod_agent.OVSBridge,
                              'db_get_val', return_value=str(old_local_vlan)),
            mock.patch.object(self.agent, 'ryu_send_msg')
        ) as (set_ovs_db_func, get_ovs_db_func, ryu_send_msg_func):
            self.agent.port_bound(port, net_uuid, 'local', None, None)
        get_ovs_db_func.assert_called_once_with("Port", mock.ANY, "tag")
        if new_local_vlan != old_local_vlan:
            set_ovs_db_func.assert_called_once_with(
                "Port", mock.ANY, "tag", str(new_local_vlan))
            if ofport != -1:
                ryu_send_msg_func.assert_called_once_with(
                    self.ofparser.OFPFlowMod.return_value)
            else:
                self.assertFalse(ryu_send_msg_func.called)
        else:
            self.assertFalse(set_ovs_db_func.called)
            self.assertFalse(ryu_send_msg_func.called)

    def test_port_bound_deletes_flows_for_valid_ofport(self):
        self._mock_port_bound(ofport=1, new_local_vlan=1)

    def test_port_bound_ignores_flows_for_invalid_ofport(self):
        self._mock_port_bound(ofport=-1, new_local_vlan=1)

    def test_port_bound_does_not_rewire_if_already_bound(self):
        self._mock_port_bound(ofport=-1, new_local_vlan=1, old_local_vlan=1)

    def _test_port_dead(self, cur_tag=None):
        port = mock.Mock()
        port.ofport = 1
        with contextlib.nested(
            mock.patch.object(self.mod_agent.OVSBridge,
                              'set_db_attribute', return_value=True),
            mock.patch.object(self.mod_agent.OVSBridge,
                              'db_get_val', return_value=cur_tag),
            mock.patch.object(self.agent, 'ryu_send_msg')
        ) as (set_ovs_db_func, get_ovs_db_func, ryu_send_msg_func):
            self.agent.port_dead(port)
        get_ovs_db_func.assert_called_once_with("Port", mock.ANY, "tag")
        if cur_tag == self.mod_agent.DEAD_VLAN_TAG:
            self.assertFalse(set_ovs_db_func.called)
            self.assertFalse(ryu_send_msg_func.called)
        else:
            set_ovs_db_func.assert_called_once_with(
                "Port", mock.ANY, "tag", str(self.mod_agent.DEAD_VLAN_TAG))
            ryu_send_msg_func.assert_called_once_with(
                self.ofparser.OFPFlowMod.return_value)

    def test_port_dead(self):
        self._test_port_dead()

    def test_port_dead_with_port_already_dead(self):
        self._test_port_dead(self.mod_agent.DEAD_VLAN_TAG)

    def mock_scan_ports(self, vif_port_set=None, registered_ports=None,
                        updated_ports=None, port_tags_dict=None):
        port_tags_dict = port_tags_dict or {}
        with contextlib.nested(
            mock.patch.object(self.agent.int_br, 'get_vif_port_set',
                              return_value=vif_port_set),
            mock.patch.object(self.agent.int_br, 'get_port_tag_dict',
                              return_value=port_tags_dict)
        ):
            return self.agent.scan_ports(registered_ports, updated_ports)

    def test_scan_ports_returns_current_only_for_unchanged_ports(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 3])
        expected = {'current': vif_port_set}
        actual = self.mock_scan_ports(vif_port_set, registered_ports)
        self.assertEqual(expected, actual)

    def test_scan_ports_returns_port_changes(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        expected = dict(current=vif_port_set, added=set([3]), removed=set([2]))
        actual = self.mock_scan_ports(vif_port_set, registered_ports)
        self.assertEqual(expected, actual)

    def _test_scan_ports_with_updated_ports(self, updated_ports):
        vif_port_set = set([1, 3, 4])
        registered_ports = set([1, 2, 4])
        expected = dict(current=vif_port_set, added=set([3]),
                        removed=set([2]), updated=set([4]))
        actual = self.mock_scan_ports(vif_port_set, registered_ports,
                                      updated_ports)
        self.assertEqual(expected, actual)

    def test_scan_ports_finds_known_updated_ports(self):
        self._test_scan_ports_with_updated_ports(set([4]))

    def test_scan_ports_ignores_unknown_updated_ports(self):
        # the port '5' was not seen on current ports. Hence it has either
        # never been wired or already removed and should be ignored
        self._test_scan_ports_with_updated_ports(set([4, 5]))

    def test_scan_ports_ignores_updated_port_if_removed(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        updated_ports = set([1, 2])
        expected = dict(current=vif_port_set, added=set([3]),
                        removed=set([2]), updated=set([1]))
        actual = self.mock_scan_ports(vif_port_set, registered_ports,
                                      updated_ports)
        self.assertEqual(expected, actual)

    def test_scan_ports_no_vif_changes_returns_updated_port_only(self):
        vif_port_set = set([1, 2, 3])
        registered_ports = set([1, 2, 3])
        updated_ports = set([2])
        expected = dict(current=vif_port_set, updated=set([2]))
        actual = self.mock_scan_ports(vif_port_set, registered_ports,
                                      updated_ports)
        self.assertEqual(expected, actual)

    def test_update_ports_returns_lost_vlan_port(self):
        br = self.mod_agent.OVSBridge('br-int', 'fake_helper', self.ryuapp)
        mac = "ca:fe:de:ad:be:ef"
        port = ovs_lib.VifPort(1, 1, 1, mac, br)
        lvm = self.mod_agent.LocalVLANMapping(
            1, '1', None, 1, {port.vif_id: port})
        local_vlan_map = {'1': lvm}
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        port_tags_dict = {1: []}
        expected = dict(
            added=set([3]), current=vif_port_set,
            removed=set([2]), updated=set([1])
        )
        with mock.patch.dict(self.agent.local_vlan_map, local_vlan_map):
            actual = self.mock_scan_ports(
                vif_port_set, registered_ports, port_tags_dict=port_tags_dict)
        self.assertEqual(expected, actual)

    def test_treat_devices_added_returns_true_for_missing_device(self):
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'get_device_details',
                              side_effect=Exception()),
            mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                              return_value=mock.Mock())):
            self.assertTrue(self.agent.treat_devices_added_or_updated([{}]))

    def _mock_treat_devices_added_updated(self, details, port, func_name):
        """Mock treat devices added or updated.

        :param details: the details to return for the device
        :param port: the port that get_vif_port_by_id should return
        :param func_name: the function that should be called
        :returns: whether the named function was called
        """
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'get_device_details',
                              return_value=details),
            mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                              return_value=port),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up'),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_down'),
            mock.patch.object(self.agent, func_name)
        ) as (get_dev_fn, get_vif_func, upd_dev_up, upd_dev_down, func):
            self.assertFalse(self.agent.treat_devices_added_or_updated([{}]))
        return func.called

    def test_treat_devices_added_updated_ignores_invalid_ofport(self):
        port = mock.Mock()
        port.ofport = -1
        self.assertFalse(self._mock_treat_devices_added_updated(
            mock.MagicMock(), port, 'port_dead'))

    def test_treat_devices_added_updated_marks_unknown_port_as_dead(self):
        port = mock.Mock()
        port.ofport = 1
        self.assertTrue(self._mock_treat_devices_added_updated(
            mock.MagicMock(), port, 'port_dead'))

    def test_treat_devices_added_does_not_process_missing_port(self):
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'get_device_details'),
            mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                              return_value=None)
        ) as (get_dev_fn, get_vif_func):
            self.assertFalse(get_dev_fn.called)

    def test_treat_devices_added_updated_updates_known_port(self):
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        self.assertTrue(self._mock_treat_devices_added_updated(
            details, mock.Mock(), 'treat_vif_port'))

    def test_treat_devices_added_updated_put_port_down(self):
        fake_details_dict = {'admin_state_up': False,
                             'port_id': 'xxx',
                             'device': 'xxx',
                             'network_id': 'yyy',
                             'physical_network': 'foo',
                             'segmentation_id': 'bar',
                             'network_type': 'baz'}
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'get_device_details',
                              return_value=fake_details_dict),
            mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                              return_value=mock.MagicMock()),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up'),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_down'),
            mock.patch.object(self.agent, 'treat_vif_port')
        ) as (get_dev_fn, get_vif_func, upd_dev_up,
              upd_dev_down, treat_vif_port):
            self.assertFalse(self.agent.treat_devices_added_or_updated([{}]))
            self.assertTrue(treat_vif_port.called)
            self.assertTrue(upd_dev_down.called)

    def test_treat_devices_removed_returns_true_for_missing_device(self):
        with mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                               side_effect=Exception()):
            self.assertTrue(self.agent.treat_devices_removed([{}]))

    def _mock_treat_devices_removed(self, port_exists):
        details = dict(exists=port_exists)
        with mock.patch.object(self.agent.plugin_rpc, 'update_device_down',
                               return_value=details):
            with mock.patch.object(self.agent, 'port_unbound') as port_unbound:
                self.assertFalse(self.agent.treat_devices_removed([{}]))
        self.assertTrue(port_unbound.called)

    def test_treat_devices_removed_unbinds_port(self):
        self._mock_treat_devices_removed(True)

    def test_treat_devices_removed_ignores_missing_port(self):
        self._mock_treat_devices_removed(False)

    def _test_process_network_ports(self, port_info):
        with contextlib.nested(
            mock.patch.object(self.agent.sg_agent, "setup_port_filters"),
            mock.patch.object(self.agent, "treat_devices_added_or_updated",
                              return_value=False),
            mock.patch.object(self.agent, "treat_devices_removed",
                              return_value=False)
        ) as (setup_port_filters, device_added_updated, device_removed):
            self.assertFalse(self.agent.process_network_ports(port_info))
            setup_port_filters.assert_called_once_with(
                port_info['added'], port_info.get('updated', set()))
            device_added_updated.assert_called_once_with(
                port_info['added'] | port_info.get('updated', set()))
            device_removed.assert_called_once_with(port_info['removed'])

    def test_process_network_ports(self):
        self._test_process_network_ports(
            {'current': set(['tap0']),
             'removed': set(['eth0']),
             'added': set(['eth1'])})

    def test_process_network_port_with_updated_ports(self):
        self._test_process_network_ports(
            {'current': set(['tap0', 'tap1']),
             'updated': set(['tap1', 'eth1']),
             'removed': set(['eth0']),
             'added': set(['eth1'])})

    def test_report_state(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state") as report_st:
            self.agent.int_br_device_count = 5
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state)
            self.assertNotIn("start_flag", self.agent.agent_state)
            self.assertEqual(
                self.agent.agent_state["configurations"]["devices"],
                self.agent.int_br_device_count
            )

    def test_network_delete(self):
        with mock.patch.object(self.agent,
                               "reclaim_local_vlan") as recl_fn:
            self.agent.network_delete("unused_context",
                                      network_id="123")
            self.assertFalse(recl_fn.called)
            self.agent.local_vlan_map["123"] = "LVM object"
            self.agent.network_delete("unused_context",
                                      network_id="123")
            recl_fn.assert_called_with("123")

    def test_port_update(self):
        port = {"id": "123",
                "network_id": "124",
                "admin_state_up": False}
        self.agent.port_update("unused_context",
                               port=port,
                               network_type="vlan",
                               segmentation_id="1",
                               physical_network="physnet")
        self.assertEqual(set(['123']), self.agent.updated_ports)

    def test_setup_physical_bridges(self):
        with contextlib.nested(
            mock.patch.object(ip_lib, "device_exists"),
            mock.patch.object(utils, "execute"),
            mock.patch.object(self.mod_agent.OVSBridge, "add_port"),
            mock.patch.object(self.mod_agent.OVSBridge, "delete_port"),
            mock.patch.object(self.mod_agent.OVSBridge, "set_protocols"),
            mock.patch.object(self.mod_agent.OVSBridge, "set_controller"),
            mock.patch.object(self.mod_agent.OVSBridge, "get_datapath_id",
                              return_value='0xa'),
            mock.patch.object(self.agent.int_br, "add_port"),
            mock.patch.object(self.agent.int_br, "delete_port"),
            mock.patch.object(ip_lib.IPWrapper, "add_veth"),
            mock.patch.object(ip_lib.IpLinkCommand, "delete"),
            mock.patch.object(ip_lib.IpLinkCommand, "set_up"),
            mock.patch.object(ip_lib.IpLinkCommand, "set_mtu"),
            mock.patch.object(self.mod_agent.ryu_api, "get_datapath",
                              return_value=self.datapath)
        ) as (devex_fn, utilsexec_fn,
              ovs_addport_fn, ovs_delport_fn, ovs_set_protocols_fn,
              ovs_set_controller_fn, ovs_datapath_id_fn, br_addport_fn,
              br_delport_fn, addveth_fn, linkdel_fn, linkset_fn, linkmtu_fn,
              ryu_api_fn):
            devex_fn.return_value = True
            parent = mock.MagicMock()
            parent.attach_mock(utilsexec_fn, 'utils_execute')
            parent.attach_mock(linkdel_fn, 'link_delete')
            parent.attach_mock(addveth_fn, 'add_veth')
            addveth_fn.return_value = (ip_lib.IPDevice("int-br-eth1"),
                                       ip_lib.IPDevice("phy-br-eth1"))
            ovs_addport_fn.return_value = "25"
            br_addport_fn.return_value = "11"
            self.agent.setup_physical_bridges({"physnet1": "br-eth"})
            expected_calls = [mock.call.link_delete(),
                              mock.call.utils_execute(['/sbin/udevadm',
                                                       'settle',
                                                       '--timeout=10']),
                              mock.call.add_veth('int-br-eth',
                                                 'phy-br-eth')]
            parent.assert_has_calls(expected_calls, any_order=False)
            self.assertEqual(self.agent.int_ofports["physnet1"],
                             "11")
            self.assertEqual(self.agent.phys_ofports["physnet1"],
                             "25")

    def test_port_unbound(self):
        with mock.patch.object(self.agent, "reclaim_local_vlan") as reclvl_fn:
            self.agent.enable_tunneling = True
            lvm = mock.Mock()
            lvm.network_type = "gre"
            lvm.vif_ports = {"vif1": mock.Mock()}
            self.agent.local_vlan_map["netuid12345"] = lvm
            self.agent.port_unbound("vif1", "netuid12345")
            self.assertTrue(reclvl_fn.called)
            reclvl_fn.called = False

            lvm.vif_ports = {}
            self.agent.port_unbound("vif1", "netuid12345")
            self.assertEqual(reclvl_fn.call_count, 2)

            lvm.vif_ports = {"vif1": mock.Mock()}
            self.agent.port_unbound("vif3", "netuid12345")
            self.assertEqual(reclvl_fn.call_count, 2)

    def _check_ovs_vxlan_version(self, installed_usr_version,
                                 installed_klm_version,
                                 installed_kernel_version,
                                 expecting_ok):
        with mock.patch(
                'neutron.agent.linux.ovs_lib.get_installed_ovs_klm_version'
        ) as klm_cmd:
            with mock.patch(
                'neutron.agent.linux.ovs_lib.get_installed_ovs_usr_version'
            ) as usr_cmd:
                with mock.patch(
                    'neutron.agent.linux.ovs_lib.get_installed_kernel_version'
                ) as krn_cmd:
                    try:
                        klm_cmd.return_value = installed_klm_version
                        usr_cmd.return_value = installed_usr_version
                        krn_cmd.return_value = installed_kernel_version
                        self.agent.tunnel_types = 'vxlan'
                        self.agent._check_ovs_version()
                        version_ok = True
                    except SystemExit as e:
                        self.assertEqual(e.code, 1)
                        version_ok = False
                self.assertEqual(version_ok, expecting_ok)

    def test_check_minimum_version(self):
        min_vxlan_ver = constants.MINIMUM_OVS_VXLAN_VERSION
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(min_vxlan_ver, min_vxlan_ver,
                                      min_kernel_ver, expecting_ok=True)

    def test_check_future_version(self):
        install_ver = str(float(constants.MINIMUM_OVS_VXLAN_VERSION) + 0.01)
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(install_ver, install_ver,
                                      min_kernel_ver, expecting_ok=True)

    def test_check_fail_version(self):
        install_ver = str(float(constants.MINIMUM_OVS_VXLAN_VERSION) - 0.01)
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(install_ver, install_ver,
                                      min_kernel_ver, expecting_ok=False)

    def test_check_fail_no_version(self):
        min_kernel_ver = constants.MINIMUM_LINUX_KERNEL_OVS_VXLAN
        self._check_ovs_vxlan_version(None, None,
                                      min_kernel_ver, expecting_ok=False)

    def test_check_fail_klm_version(self):
        min_vxlan_ver = constants.MINIMUM_OVS_VXLAN_VERSION
        min_kernel_ver = OVS_LINUX_KERN_VERS_WITHOUT_VXLAN
        install_ver = str(float(min_vxlan_ver) - 0.01)
        self._check_ovs_vxlan_version(min_vxlan_ver, install_ver,
                                      min_kernel_ver, expecting_ok=False)

    def test_daemon_loop_uses_polling_manager(self):
        with mock.patch(
            'neutron.agent.linux.polling.get_polling_manager'
        ) as mock_get_pm:
            fake_pm = mock.Mock()
            mock_get_pm.return_value = fake_pm
            fake_pm.__enter__ = mock.Mock()
            fake_pm.__exit__ = mock.Mock()
            with mock.patch.object(
                self.agent, 'ovsdb_monitor_loop'
            ) as mock_loop:
                self.agent.daemon_loop()
        mock_get_pm.assert_called_once_with(True, 'fake_helper',
                                            constants.DEFAULT_OVSDBMON_RESPAWN)
        mock_loop.assert_called_once_with(polling_manager=fake_pm.__enter__())

    def test_setup_tunnel_port_error_negative(self):
        with contextlib.nested(
            mock.patch.object(self.agent.tun_br, 'add_tunnel_port',
                              return_value='-1'),
            mock.patch.object(self.mod_agent.LOG, 'error')
        ) as (add_tunnel_port_fn, log_error_fn):
            ofport = self.agent.setup_tunnel_port(
                'gre-1', 'remote_ip', p_const.TYPE_GRE)
            add_tunnel_port_fn.assert_called_once_with(
                'gre-1', 'remote_ip', self.agent.local_ip, p_const.TYPE_GRE,
                self.agent.vxlan_udp_port)
            log_error_fn.assert_called_once_with(
                _("Failed to set-up %(type)s tunnel port to %(ip)s"),
                {'type': p_const.TYPE_GRE, 'ip': 'remote_ip'})
            self.assertEqual(ofport, 0)

    def test_setup_tunnel_port_error_not_int(self):
        with contextlib.nested(
            mock.patch.object(self.agent.tun_br, 'add_tunnel_port',
                              return_value=None),
            mock.patch.object(self.mod_agent.LOG, 'exception'),
            mock.patch.object(self.mod_agent.LOG, 'error')
        ) as (add_tunnel_port_fn, log_exc_fn, log_error_fn):
            ofport = self.agent.setup_tunnel_port(
                'gre-1', 'remote_ip', p_const.TYPE_GRE)
            add_tunnel_port_fn.assert_called_once_with(
                'gre-1', 'remote_ip', self.agent.local_ip, p_const.TYPE_GRE,
                self.agent.vxlan_udp_port)
            log_exc_fn.assert_called_once_with(
                _("ofport should have a value that can be "
                  "interpreted as an integer"))
            log_error_fn.assert_called_once_with(
                _("Failed to set-up %(type)s tunnel port to %(ip)s"),
                {'type': p_const.TYPE_GRE, 'ip': 'remote_ip'})
            self.assertEqual(ofport, 0)

    def _create_tunnel_port_name(self, tunnel_ip, tunnel_type):
        tunnel_ip_hex = '%08x' % netaddr.IPAddress(tunnel_ip, version=4)
        return '%s-%s' % (tunnel_type, tunnel_ip_hex)

    def test_tunnel_sync_with_valid_ip_address_and_gre_type(self):
        tunnel_ip = '100.101.102.103'
        self.agent.tunnel_types = ['gre']
        tun_name = self._create_tunnel_port_name(tunnel_ip,
                                                 self.agent.tunnel_types[0])
        fake_tunnel_details = {'tunnels': [{'ip_address': tunnel_ip}]}
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'tunnel_sync',
                              return_value=fake_tunnel_details),
            mock.patch.object(self.agent, 'setup_tunnel_port')
        ) as (tunnel_sync_rpc_fn, setup_tunnel_port_fn):
            self.agent.tunnel_sync()
            expected_calls = [mock.call(tun_name, tunnel_ip,
                                        self.agent.tunnel_types[0])]
            setup_tunnel_port_fn.assert_has_calls(expected_calls)

    def test_tunnel_sync_with_valid_ip_address_and_vxlan_type(self):
        tunnel_ip = '100.101.31.15'
        self.agent.tunnel_types = ['vxlan']
        tun_name = self._create_tunnel_port_name(tunnel_ip,
                                                 self.agent.tunnel_types[0])
        fake_tunnel_details = {'tunnels': [{'ip_address': tunnel_ip}]}
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'tunnel_sync',
                              return_value=fake_tunnel_details),
            mock.patch.object(self.agent, 'setup_tunnel_port')
        ) as (tunnel_sync_rpc_fn, setup_tunnel_port_fn):
            self.agent.tunnel_sync()
            expected_calls = [mock.call(tun_name, tunnel_ip,
                                        self.agent.tunnel_types[0])]
            setup_tunnel_port_fn.assert_has_calls(expected_calls)

    def test_tunnel_sync_invalid_ip_address(self):
        tunnel_ip = '100.100.100.100'
        self.agent.tunnel_types = ['vxlan']
        tun_name = self._create_tunnel_port_name(tunnel_ip,
                                                 self.agent.tunnel_types[0])
        fake_tunnel_details = {'tunnels': [{'ip_address': '300.300.300.300'},
                                           {'ip_address': tunnel_ip}]}
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'tunnel_sync',
                              return_value=fake_tunnel_details),
            mock.patch.object(self.agent, 'setup_tunnel_port')
        ) as (tunnel_sync_rpc_fn, setup_tunnel_port_fn):
            self.agent.tunnel_sync()
            setup_tunnel_port_fn.assert_called_once_with(
                tun_name, tunnel_ip, self.agent.tunnel_types[0])

    def test_tunnel_update(self):
        tunnel_ip = '10.10.10.10'
        self.agent.tunnel_types = ['gre']
        tun_name = self._create_tunnel_port_name(tunnel_ip,
                                                 self.agent.tunnel_types[0])
        kwargs = {'tunnel_ip': tunnel_ip,
                  'tunnel_type': self.agent.tunnel_types[0]}
        self.agent.setup_tunnel_port = mock.Mock()
        self.agent.enable_tunneling = True
        self.agent.l2_pop = False
        self.agent.tunnel_update(context=None, **kwargs)
        expected_calls = [mock.call(tun_name, tunnel_ip,
                                    self.agent.tunnel_types[0])]
        self.agent.setup_tunnel_port.assert_has_calls(expected_calls)

    def test__provision_local_vlan_inbound_for_tunnel(self):
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._provision_local_vlan_inbound_for_tunnel(1, 'gre', 3)

        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        expected_msg = ofpp.OFPFlowMod(
            self.agent.tun_br.datapath,
            instructions=[
                ofpp.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofpp.OFPActionPushVlan(),
                        ofpp.OFPActionSetField(vlan_vid=1 |
                                               ofp.OFPVID_PRESENT),
                    ]),
                ofpp.OFPInstructionGotoTable(table_id=10),
            ],
            match=ofpp.OFPMatch(tunnel_id=3),
            priority=1,
            table_id=2)
        sendmsg.assert_has_calls([mock.call(expected_msg)])

    def test__provision_local_vlan_outbound(self):
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._provision_local_vlan_outbound(888, 999, 'phys-net1')

        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        expected_msg = ofpp.OFPFlowMod(
            self.agent.phys_brs['phys-net1'].datapath,
            instructions=[
                ofpp.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofpp.OFPActionSetField(vlan_vid=999),
                        ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
                    ]
                )
            ],
            match=ofpp.OFPMatch(
                in_port=777,
                vlan_vid=888 | ofp.OFPVID_PRESENT
            ),
            priority=4)
        sendmsg.assert_has_calls([mock.call(expected_msg)])

    def test__provision_local_vlan_inbound(self):
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._provision_local_vlan_inbound(888, 999, 'phys-net1')

        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        expected_msg = ofpp.OFPFlowMod(
            self.agent.int_br.datapath,
            instructions=[
                ofpp.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofpp.OFPActionSetField(
                            vlan_vid=888 | ofp.OFPVID_PRESENT
                        ),
                        ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
                    ]
                )
            ],
            match=ofpp.OFPMatch(in_port=666, vlan_vid=999),
            priority=3)
        sendmsg.assert_has_calls([mock.call(expected_msg)])

    def test__reclaim_local_vlan_outbound(self):
        lvm = mock.Mock()
        lvm.network_type = p_const.TYPE_VLAN
        lvm.segmentation_id = 555
        lvm.vlan = 444
        lvm.physical_network = 'phys-net1'
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._reclaim_local_vlan_outbound(lvm)

        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        expected_msg = ofpp.OFPFlowMod(
            self.agent.phys_brs['phys-net1'].datapath,
            command=ofp.OFPFC_DELETE,
            match=ofpp.OFPMatch(
                in_port=777,
                vlan_vid=444 | ofp.OFPVID_PRESENT
            ),
            out_group=ofp.OFPG_ANY,
            out_port=ofp.OFPP_ANY,
            table_id=ofp.OFPTT_ALL)
        sendmsg.assert_has_calls([mock.call(expected_msg)])

    def test__reclaim_local_vlan_inbound(self):
        lvm = mock.Mock()
        lvm.network_type = p_const.TYPE_VLAN
        lvm.segmentation_id = 555
        lvm.vlan = 444
        lvm.physical_network = 'phys-net1'
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._reclaim_local_vlan_inbound(lvm)

        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        expected_msg = ofpp.OFPFlowMod(
            self.agent.int_br.datapath,
            command=ofp.OFPFC_DELETE,
            match=ofpp.OFPMatch(
                in_port=666,
                vlan_vid=555 | ofp.OFPVID_PRESENT
            ),
            out_group=ofp.OFPG_ANY,
            out_port=ofp.OFPP_ANY,
            table_id=ofp.OFPTT_ALL)
        sendmsg.assert_has_calls([mock.call(expected_msg)])

    def test__provision_local_vlan_outbound_flat(self):
        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._provision_local_vlan_outbound(888, ofp.OFPVID_NONE,
                                                      'phys-net1')

        expected_msg = ofpp.OFPFlowMod(
            self.agent.phys_brs['phys-net1'].datapath,
            instructions=[
                ofpp.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofpp.OFPActionPopVlan(),
                        ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
                    ]
                )
            ],
            match=ofpp.OFPMatch(
                in_port=777,
                vlan_vid=888 | ofp.OFPVID_PRESENT
            ),
            priority=4)
        sendmsg.assert_has_calls([mock.call(expected_msg)])

    def test__provision_local_vlan_inbound_flat(self):
        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._provision_local_vlan_inbound(888, ofp.OFPVID_NONE,
                                                     'phys-net1')

        expected_msg = ofpp.OFPFlowMod(
            self.agent.int_br.datapath,
            instructions=[
                ofpp.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [
                        ofpp.OFPActionPushVlan(),
                        ofpp.OFPActionSetField(
                            vlan_vid=888 | ofp.OFPVID_PRESENT
                        ),
                        ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
                    ]
                )
            ],
            match=ofpp.OFPMatch(in_port=666, vlan_vid=ofp.OFPVID_NONE),
            priority=3)
        sendmsg.assert_has_calls([mock.call(expected_msg)])

    def test__reclaim_local_vlan_outbound_flat(self):
        lvm = mock.Mock()
        lvm.network_type = p_const.TYPE_FLAT
        lvm.segmentation_id = 555
        lvm.vlan = 444
        lvm.physical_network = 'phys-net1'
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._reclaim_local_vlan_outbound(lvm)

        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        expected_msg = ofpp.OFPFlowMod(
            self.agent.phys_brs['phys-net1'].datapath,
            command=ofp.OFPFC_DELETE,
            match=ofpp.OFPMatch(
                in_port=777,
                vlan_vid=444 | ofp.OFPVID_PRESENT
            ),
            out_group=ofp.OFPG_ANY,
            out_port=ofp.OFPP_ANY,
            table_id=ofp.OFPTT_ALL)
        sendmsg.assert_has_calls([mock.call(expected_msg)])

    def test__reclaim_local_vlan_inbound_flat(self):
        lvm = mock.Mock()
        lvm.network_type = p_const.TYPE_FLAT
        lvm.segmentation_id = 555
        lvm.vlan = 444
        lvm.physical_network = 'phys-net1'
        with mock.patch.object(self.agent, 'ryu_send_msg') as sendmsg:
            self.agent._reclaim_local_vlan_inbound(lvm)

        ofp = importutils.import_module('ryu.ofproto.ofproto_v1_3')
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        expected_msg = ofpp.OFPFlowMod(
            self.agent.int_br.datapath,
            command=ofp.OFPFC_DELETE,
            match=ofpp.OFPMatch(
                in_port=666,
                vlan_vid=ofp.OFPVID_NONE
            ),
            out_group=ofp.OFPG_ANY,
            out_port=ofp.OFPP_ANY,
            table_id=ofp.OFPTT_ALL)
        sendmsg.assert_has_calls([mock.call(expected_msg)])


class AncillaryBridgesTest(OFAAgentTestCase):

    def setUp(self):
        super(AncillaryBridgesTest, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        # Avoid rpc initialization for unit tests
        cfg.CONF.set_override('rpc_backend',
                              'neutron.openstack.common.rpc.impl_fake')
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        self.kwargs = self.mod_agent.create_agent_config_map(cfg.CONF)

    def _test_ancillary_bridges(self, bridges, ancillary):
        device_ids = ancillary[:]

        def pullup_side_effect(self, *args):
            result = device_ids.pop(0)
            return result

        with contextlib.nested(
            mock.patch.object(self.mod_agent.OFANeutronAgent,
                              'setup_integration_br',
                              return_value=mock.Mock()),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch.object(self.mod_agent.OVSBridge,
                              'get_local_port_mac',
                              return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.ovs_lib.get_bridges',
                       return_value=bridges),
            mock.patch(
                'neutron.agent.linux.ovs_lib.get_bridge_external_bridge_id',
                side_effect=pullup_side_effect)):
            self.agent = self.mod_agent.OFANeutronAgent(
                self.ryuapp, **self.kwargs)
            self.assertEqual(len(ancillary), len(self.agent.ancillary_brs))
            if ancillary:
                bridges = [br.br_name for br in self.agent.ancillary_brs]
                for br in ancillary:
                    self.assertIn(br, bridges)

    def test_ancillary_bridges_single(self):
        bridges = ['br-int', 'br-ex']
        self._test_ancillary_bridges(bridges, ['br-ex'])

    def test_ancillary_bridges_none(self):
        bridges = ['br-int']
        self._test_ancillary_bridges(bridges, [])

    def test_ancillary_bridges_multiple(self):
        bridges = ['br-int', 'br-ex1', 'br-ex2']
        self._test_ancillary_bridges(bridges, ['br-ex1', 'br-ex2'])
