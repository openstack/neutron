# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 Fumihiko Kakuma <kakuma at valinux co jp>
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
# All Rights Reserved.
#
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

import collections
import contextlib
import copy

import mock
import netaddr
from oslo.config import cfg
import testtools

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants as n_const
from neutron.openstack.common import importutils
from neutron.plugins.common import constants as p_const
from neutron.tests.unit.ofagent import ofa_test_base


NOTIFIER = ('neutron.plugins.ml2.rpc.AgentNotifierApi')


def _mock_port(is_neutron=True, normalized_name=None):
    p = mock.Mock()
    p.is_neutron_port.return_value = is_neutron
    if normalized_name:
        p.normalized_port_name.return_value = normalized_name
    return p


class CreateAgentConfigMap(ofa_test_base.OFAAgentTestBase):

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


class TestOFANeutronAgentBridge(ofa_test_base.OFAAgentTestBase):

    def setUp(self):
        super(TestOFANeutronAgentBridge, self).setUp()
        self.br_name = 'bridge1'
        self.root_helper = 'fake_helper'
        self.ovs = self.mod_agent.Bridge(
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


class TestOFANeutronAgent(ofa_test_base.OFAAgentTestBase):

    def setUp(self):
        super(TestOFANeutronAgent, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        kwargs = self.mod_agent.create_agent_config_map(cfg.CONF)

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        with contextlib.nested(
            mock.patch.object(self.mod_agent.OFANeutronAgent,
                              'setup_integration_br',
                              return_value=mock.Mock()),
            mock.patch.object(self.mod_agent.Bridge,
                              'get_local_port_mac',
                              return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.openstack.common.loopingcall.'
                       'FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall)):
            self.agent = self.mod_agent.OFANeutronAgent(self.ryuapp, **kwargs)

        self.agent.sg_agent = mock.Mock()
        self.int_dp = self._mk_test_dp('int_br')
        self.agent.int_br = self._mk_test_br('int_br')
        self.agent.int_br.set_dp(self.int_dp)
        self.agent.phys_brs['phys-net1'] = self._mk_test_br('phys_br1')
        self.agent.phys_ofports['phys-net1'] = 777
        self.agent.int_ofports['phys-net1'] = 666
        self.datapath = self._mk_test_dp('phys_br')

    def _create_tunnel_port_name(self, tunnel_ip, tunnel_type):
        tunnel_ip_hex = '%08x' % netaddr.IPAddress(tunnel_ip, version=4)
        return '%s-%s' % (tunnel_type, tunnel_ip_hex)

    def mock_scan_ports(self, port_set=None, registered_ports=None,
                        updated_ports=None, port_tags_dict=None):
        port_tags_dict = port_tags_dict or {}
        with contextlib.nested(
            mock.patch.object(self.agent, '_get_ofport_names',
                              return_value=port_set),
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

    def test_treat_devices_added_returns_true_for_missing_device(self):
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'get_device_details',
                              side_effect=Exception()),
            mock.patch.object(self.agent, '_get_ports',
                              return_value=[_mock_port(True, 'xxx')])):
            self.assertTrue(self.agent.treat_devices_added_or_updated(['xxx']))

    def _mock_treat_devices_added_updated(self, details, port, all_ports,
                                          func_name):
        """Mock treat devices added or updated.

        :param details: the details to return for the device
        :param port: port name to process
        :param all_ports: the port that _get_ports return
        :param func_name: the function that should be called
        :returns: whether the named function was called
        """
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'get_device_details',
                              return_value=details),
            mock.patch.object(self.agent, '_get_ports',
                              return_value=all_ports),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up'),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_down'),
            mock.patch.object(self.agent, func_name)
        ) as (get_dev_fn, _get_ports, upd_dev_up, upd_dev_down, func):
            self.assertFalse(self.agent.treat_devices_added_or_updated([port]))
        _get_ports.assert_called_once_with(self.agent.int_br)
        return func.called

    def test_treat_devices_added_updated_ignores_invalid_ofport(self):
        port_name = 'hoge'
        p1 = _mock_port(True, port_name)
        p1.ofport = -1
        self.assertFalse(self._mock_treat_devices_added_updated(
            mock.MagicMock(), port_name, [p1], 'port_dead'))

    def test_treat_devices_added_updated_marks_unknown_port_as_dead(self):
        port_name = 'hoge'
        p1 = _mock_port(True, port_name)
        p1.ofport = 1
        self.assertTrue(self._mock_treat_devices_added_updated(
            mock.MagicMock(), port_name, [p1], 'port_dead'))

    def test_treat_devices_added_does_not_process_missing_port(self):
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'get_device_details'),
            mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                              return_value=None)
        ) as (get_dev_fn, get_vif_func):
            self.assertFalse(get_dev_fn.called)

    def test_treat_devices_added_updated_updates_known_port(self):
        port_name = 'tapd3315981-0b'
        p1 = _mock_port(False)
        p2 = _mock_port(True, port_name)
        ports = [p1, p2]
        details = mock.MagicMock()
        details.__contains__.side_effect = lambda x: True
        self.assertTrue(self._mock_treat_devices_added_updated(
            details, port_name, ports, 'treat_vif_port'))

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
            mock.patch.object(self.agent, '_get_ports',
                              return_value=[_mock_port(True, 'xxx')]),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up'),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_down'),
            mock.patch.object(self.agent, 'treat_vif_port')
        ) as (get_dev_fn, _get_ports, upd_dev_up,
              upd_dev_down, treat_vif_port):
            self.assertFalse(self.agent.treat_devices_added_or_updated(
                ['xxx']))
            self.assertTrue(treat_vif_port.called)
            self.assertTrue(upd_dev_down.called)
        _get_ports.assert_called_once_with(self.agent.int_br)

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

    def test_port_update(self):
        port = {"id": "b1981919-f516-11e3-a8f4-08606e7f74e7",
                "network_id": "124",
                "admin_state_up": False}
        self.agent.port_update("unused_context",
                               port=port,
                               network_type="vlan",
                               segmentation_id="1",
                               physical_network="physnet")
        self.assertEqual(set(['tapb1981919-f5']), self.agent.updated_ports)

    def test_setup_physical_bridges(self):
        with contextlib.nested(
            mock.patch.object(ip_lib, "device_exists"),
            mock.patch.object(utils, "execute"),
            mock.patch.object(self.mod_agent.Bridge, "add_port"),
            mock.patch.object(self.mod_agent.Bridge, "delete_port"),
            mock.patch.object(self.mod_agent.Bridge, "set_protocols"),
            mock.patch.object(self.mod_agent.Bridge, "set_controller"),
            mock.patch.object(self.mod_agent.Bridge, "get_datapath_id",
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
            self.assertEqual(11, self.agent.int_ofports["physnet1"])
            self.assertEqual(25, self.agent.phys_ofports["physnet1"])

    def test_setup_physical_interfaces(self):
        with mock.patch.object(self.agent.int_br, "add_port") as add_port_fn:
            add_port_fn.return_value = "111"
            self.agent.setup_physical_interfaces({"physnet1": "eth1"})
            add_port_fn.assert_called_once_with("eth1")
            self.assertEqual(111, self.agent.int_ofports["physnet1"])

    def test_port_unbound(self):
        with contextlib.nested(
            mock.patch.object(self.agent, "reclaim_local_vlan"),
            mock.patch.object(self.agent, "get_net_uuid",
                              return_value="netuid12345"),
        ) as (reclvl_fn, _):
            self.agent.enable_tunneling = True
            lvm = mock.Mock()
            lvm.network_type = "gre"
            lvm.vif_ports = {"vif1": mock.Mock()}
            self.agent.local_vlan_map["netuid12345"] = lvm
            self.agent.port_unbound("vif1")
            self.assertTrue(reclvl_fn.called)

    def _prepare_l2_pop_ofports(self, network_type=None):
        LVM = collections.namedtuple('LVM', 'net, vlan, segid, ip')
        self.lvms = [LVM(net='net1', vlan=11, segid=21, ip='1.1.1.1'),
                     LVM(net='net2', vlan=12, segid=22, ip='2.2.2.2')]
        self.tunnel_type = 'gre'
        self.tun_name1 = self._create_tunnel_port_name(self.lvms[0].ip,
                                                       self.tunnel_type)
        self.tun_name2 = self._create_tunnel_port_name(self.lvms[1].ip,
                                                       self.tunnel_type)
        if network_type is None:
            network_type = self.tunnel_type
        lvm1 = mock.Mock()
        lvm1.network_type = network_type
        lvm1.vlan = self.lvms[0].vlan
        lvm1.segmentation_id = self.lvms[0].segid
        lvm1.tun_ofports = set([1])
        lvm2 = mock.Mock()
        lvm2.network_type = network_type
        lvm2.vlan = self.lvms[1].vlan
        lvm2.segmentation_id = self.lvms[1].segid
        lvm2.tun_ofports = set([1, 2])
        self.agent.tunnel_types = [self.tunnel_type]
        self.agent.local_vlan_map = {self.lvms[0].net: lvm1,
                                     self.lvms[1].net: lvm2}
        self.agent.tun_ofports = {self.tunnel_type:
                                  {self.lvms[0].ip: 1,
                                   self.lvms[1].ip: 2}}

    def test_fdb_ignore_network(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {'net3': {}}
        with contextlib.nested(
            mock.patch.object(self.agent, '_setup_tunnel_port'),
            mock.patch.object(self.agent, 'cleanup_tunnel_port')
        ) as (add_tun_fn, clean_tun_fn):
            self.agent.fdb_add(None, fdb_entry)
            self.assertFalse(add_tun_fn.called)
            self.agent.fdb_remove(None, fdb_entry)
            self.assertFalse(clean_tun_fn.called)

    def test_fdb_ignore_self(self):
        self._prepare_l2_pop_ofports()
        self.agent.local_ip = 'agent_ip'
        fdb_entry = {self.lvms[1].net:
                     {'network_type': self.tunnel_type,
                      'segment_id': 'tun2',
                      'ports':
                      {'agent_ip':
                       [['mac', 'ip'],
                        n_const.FLOODING_ENTRY]}}}
        with contextlib.nested(
            mock.patch.object(self.agent.ryuapp, "add_arp_table_entry"),
            mock.patch.object(self.agent.ryuapp, "del_arp_table_entry"),
        ) as (add_fn, del_fn):
            self.agent.fdb_add(None, copy.deepcopy(fdb_entry))
            add_fn.assert_called_once_with(12, 'ip', 'mac')
            self.assertFalse(del_fn.called)
            self.agent.fdb_remove(None, fdb_entry)
            add_fn.assert_called_once_with(12, 'ip', 'mac')
            del_fn.assert_called_once_with(12, 'ip')

    def test_fdb_add_flows(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {self.lvms[0].net:
                     {'network_type': self.tunnel_type,
                      'segment_id': 'tun1',
                      'ports':
                      {self.lvms[1].ip:
                       [['mac', 'ip'],
                        n_const.FLOODING_ENTRY]}}}
        with contextlib.nested(
            mock.patch.object(self.agent, '_setup_tunnel_port'),
            mock.patch.object(self.agent.int_br, 'install_tunnel_output'),
            mock.patch.object(self.agent.int_br, 'delete_tunnel_output'),
        ) as (add_tun_fn, install_fn, delete_fn):
            add_tun_fn.return_value = 2
            self.agent.fdb_add(None, fdb_entry)
            self.assertEqual(2, install_fn.call_count)
            expected_calls = [
                mock.call(7, 11, 21, set([2]), eth_dst='mac', goto_next=False),
                mock.call(10, 11, 21, set([1, 2]), goto_next=True)
            ]
            install_fn.assert_has_calls(expected_calls)
            self.assertFalse(delete_fn.called)

    def test_fdb_del_flows(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {self.lvms[1].net:
                     {'network_type': self.tunnel_type,
                      'segment_id': 'tun2',
                      'ports':
                      {self.lvms[1].ip:
                       [['mac', 'ip'],
                        n_const.FLOODING_ENTRY]}}}
        with contextlib.nested(
            mock.patch.object(self.agent.int_br, 'install_tunnel_output'),
            mock.patch.object(self.agent.int_br, 'delete_tunnel_output'),
        ) as (install_fn, delete_fn):
            self.agent.fdb_remove(None, fdb_entry)
            install_fn.assert_called_once_with(10, 12, 22, set([1]),
                                               goto_next=True)
            delete_fn.assert_called_once_with(7, 12, eth_dst='mac')

    def test_fdb_add_port(self):
        self._prepare_l2_pop_ofports()
        tunnel_ip = '10.10.10.10'
        tun_name = self._create_tunnel_port_name(tunnel_ip,
                                                 self.tunnel_type)
        fdb_entry = {self.lvms[0].net:
                     {'network_type': self.tunnel_type,
                      'segment_id': 'tun1',
                      'ports': {self.lvms[0].ip: [['mac', 'ip']]}}}
        with mock.patch.object(self.agent, '_setup_tunnel_port') as add_tun_fn:
            self.agent.fdb_add(None, fdb_entry)
            self.assertFalse(add_tun_fn.called)
            fdb_entry[self.lvms[0].net]['ports'][tunnel_ip] = [['mac', 'ip']]
            self.agent.fdb_add(None, fdb_entry)
            add_tun_fn.assert_called_with(
                self.agent.int_br, tun_name, tunnel_ip, self.tunnel_type)

    def test_fdb_del_port(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {self.lvms[1].net:
                     {'network_type': self.tunnel_type,
                      'segment_id': 'tun2',
                      'ports': {self.lvms[1].ip: [n_const.FLOODING_ENTRY]}}}
        with mock.patch.object(self.agent.int_br,
                               'delete_port') as del_port_fn:
            self.agent.fdb_remove(None, fdb_entry)
            del_port_fn.assert_called_once_with(self.tun_name2)

    def test_add_arp_table_entry(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {self.lvms[0].net:
                     {'network_type': self.tunnel_type,
                      'segment_id': 'tun1',
                      'ports': {self.lvms[0].ip: [n_const.FLOODING_ENTRY,
                                                  ['mac1', 'ip1']],
                                self.lvms[1].ip: [['mac2', 'ip2']],
                                '192.0.2.1': [n_const.FLOODING_ENTRY,
                                              ['mac3', 'ip3']]}}}
        with mock.patch.object(self.agent,
                               'setup_tunnel_port') as setup_tun_fn:
            self.agent.fdb_add(None, fdb_entry)
            calls = [
                mock.call(self.agent.local_vlan_map[self.lvms[0].net].vlan,
                          'ip1', 'mac1'),
                mock.call(self.agent.local_vlan_map[self.lvms[0].net].vlan,
                          'ip2', 'mac2')
            ]
            self.ryuapp.add_arp_table_entry.assert_has_calls(calls)
            setup_tun_fn.assert_called_once_with(self.agent.int_br,
                                                 '192.0.2.1', 'gre')

    def _test_add_arp_table_entry_non_tunnel(self, network_type):
        self._prepare_l2_pop_ofports(network_type=network_type)
        fdb_entry = {self.lvms[0].net:
                     {'network_type': network_type,
                      'segment_id': 'tun1',
                      'ports': {self.lvms[0].ip: [n_const.FLOODING_ENTRY,
                                                  ['mac1', 'ip1']],
                                self.lvms[1].ip: [['mac2', 'ip2']],
                                '192.0.2.1': [n_const.FLOODING_ENTRY,
                                              ['mac3', 'ip3']]}}}
        with mock.patch.object(self.agent,
                               'setup_tunnel_port') as setup_tun_fn:
            self.agent.fdb_add(None, fdb_entry)
            calls = [
                mock.call(self.agent.local_vlan_map[self.lvms[0].net].vlan,
                          'ip1', 'mac1'),
                mock.call(self.agent.local_vlan_map[self.lvms[0].net].vlan,
                          'ip2', 'mac2')
            ]
            self.ryuapp.add_arp_table_entry.assert_has_calls(calls)
            self.assertFalse(setup_tun_fn.called)

    def test_add_arp_table_entry_vlan(self):
        self._test_add_arp_table_entry_non_tunnel('vlan')

    def test_add_arp_table_entry_flat(self):
        self._test_add_arp_table_entry_non_tunnel('flat')

    def test_add_arp_table_entry_local(self):
        self._test_add_arp_table_entry_non_tunnel('local')

    def test_del_arp_table_entry(self):
        self._prepare_l2_pop_ofports()
        fdb_entry = {self.lvms[0].net:
                     {'network_type': self.tunnel_type,
                      'segment_id': 'tun1',
                      'ports': {self.lvms[0].ip: [n_const.FLOODING_ENTRY,
                                                  ['mac1', 'ip1']],
                                self.lvms[1].ip: [['mac2', 'ip2']],
                                '192.0.2.1': [n_const.FLOODING_ENTRY,
                                              ['mac3', 'ip3']]}}}
        with mock.patch.object(self.agent,
                               'cleanup_tunnel_port') as cleanup_tun_fn:
            self.agent.fdb_remove(None, fdb_entry)
            calls = [
                mock.call(self.agent.local_vlan_map[self.lvms[0].net].vlan,
                          'ip1'),
                mock.call(self.agent.local_vlan_map[self.lvms[0].net].vlan,
                          'ip2')
            ]
            self.ryuapp.del_arp_table_entry.assert_has_calls(calls)
            cleanup_tun_fn.assert_called_once_with(self.agent.int_br, 1, 'gre')

    def _test_del_arp_table_entry_non_tunnel(self, network_type):
        self._prepare_l2_pop_ofports(network_type=network_type)
        fdb_entry = {self.lvms[0].net:
                     {'network_type': network_type,
                      'segment_id': 'tun1',
                      'ports': {self.lvms[0].ip: [n_const.FLOODING_ENTRY,
                                                  ['mac1', 'ip1']],
                                self.lvms[1].ip: [['mac2', 'ip2']],
                                '192.0.2.1': [n_const.FLOODING_ENTRY,
                                              ['mac3', 'ip3']]}}}
        with mock.patch.object(self.agent,
                               'cleanup_tunnel_port') as cleanup_tun_fn:
            self.agent.fdb_remove(None, fdb_entry)
            calls = [
                mock.call(self.agent.local_vlan_map[self.lvms[0].net].vlan,
                          'ip1'),
                mock.call(self.agent.local_vlan_map[self.lvms[0].net].vlan,
                          'ip2')
            ]
            self.ryuapp.del_arp_table_entry.assert_has_calls(calls)
            self.assertFalse(cleanup_tun_fn.called)

    def test_del_arp_table_entry_vlan(self):
        self._test_del_arp_table_entry_non_tunnel('vlan')

    def test_del_arp_table_entry_flat(self):
        self._test_del_arp_table_entry_non_tunnel('flat')

    def test_del_arp_table_entry_local(self):
        self._test_del_arp_table_entry_non_tunnel('local')

    def test_recl_lv_port_to_preserve(self):
        self._prepare_l2_pop_ofports()
        self.agent.enable_tunneling = True
        with mock.patch.object(
            self.agent.int_br, 'delete_port'
        ) as del_port_fn:
            self.agent.reclaim_local_vlan(self.lvms[0].net)
            self.assertFalse(del_port_fn.called)

    def test_recl_lv_port_to_remove(self):
        self._prepare_l2_pop_ofports()
        self.agent.enable_tunneling = True
        with mock.patch.object(self.agent.int_br,
                               'delete_port') as del_port_fn:
            self.agent.reclaim_local_vlan(self.lvms[1].net)
            del_port_fn.assert_called_once_with(self.tun_name2)

    def test__setup_tunnel_port_error_negative(self):
        with contextlib.nested(
            mock.patch.object(self.agent.int_br, 'add_tunnel_port',
                              return_value='-1'),
            mock.patch.object(self.mod_agent.LOG, 'error')
        ) as (add_tunnel_port_fn, log_error_fn):
            ofport = self.agent._setup_tunnel_port(
                self.agent.int_br, 'gre-1', 'remote_ip', p_const.TYPE_GRE)
            add_tunnel_port_fn.assert_called_once_with(
                'gre-1', 'remote_ip', self.agent.local_ip, p_const.TYPE_GRE,
                self.agent.vxlan_udp_port, self.agent.dont_fragment)
            log_error_fn.assert_called_once_with(
                _("Failed to set-up %(type)s tunnel port to %(ip)s"),
                {'type': p_const.TYPE_GRE, 'ip': 'remote_ip'})
            self.assertEqual(ofport, 0)

    def test__setup_tunnel_port_error_not_int(self):
        with contextlib.nested(
            mock.patch.object(self.agent.int_br, 'add_tunnel_port',
                              return_value=None),
            mock.patch.object(self.mod_agent.LOG, 'exception'),
            mock.patch.object(self.mod_agent.LOG, 'error')
        ) as (add_tunnel_port_fn, log_exc_fn, log_error_fn):
            ofport = self.agent._setup_tunnel_port(
                self.agent.int_br, 'gre-1', 'remote_ip', p_const.TYPE_GRE)
            add_tunnel_port_fn.assert_called_once_with(
                'gre-1', 'remote_ip', self.agent.local_ip, p_const.TYPE_GRE,
                self.agent.vxlan_udp_port, self.agent.dont_fragment)
            log_exc_fn.assert_called_once_with(
                _("ofport should have a value that can be "
                  "interpreted as an integer"))
            log_error_fn.assert_called_once_with(
                _("Failed to set-up %(type)s tunnel port to %(ip)s"),
                {'type': p_const.TYPE_GRE, 'ip': 'remote_ip'})
            self.assertEqual(ofport, 0)

    def test_tunnel_sync(self):
        self.agent.local_ip = 'agent_ip'
        self.agent.context = 'fake_context'
        self.agent.tunnel_types = ['vxlan']
        with mock.patch.object(
            self.agent.plugin_rpc, 'tunnel_sync'
        ) as tunnel_sync_rpc_fn:
            self.agent.tunnel_sync()
            tunnel_sync_rpc_fn.assert_called_once_with(
                self.agent.context,
                self.agent.local_ip,
                self.agent.tunnel_types[0])

    def test__get_ports(self):
        ofpp = importutils.import_module('ryu.ofproto.ofproto_v1_3_parser')
        reply = [ofpp.OFPPortDescStatsReply(body=[ofpp.OFPPort(name='hoge',
                                                               port_no=8)])]
        sendmsg = mock.Mock(return_value=reply)
        self.mod_agent.ryu_api.send_msg = sendmsg
        result = self.agent._get_ports(self.agent.int_br)
        result = list(result)  # convert generator to list.
        self.assertEqual(1, len(result))
        self.assertEqual('hoge', result[0].port_name)
        self.assertEqual(8, result[0].ofport)
        expected_msg = ofpp.OFPPortDescStatsRequest(
            datapath=self.agent.int_br.datapath)
        sendmsg.assert_has_calls([mock.call(app=self.agent.ryuapp,
            msg=expected_msg, reply_cls=ofpp.OFPPortDescStatsReply,
            reply_multi=True)])

    def test__get_ofport_names(self):
        names = ['p111', 'p222', 'p333']
        ps = [_mock_port(True, x) for x in names]
        with mock.patch.object(self.agent, '_get_ports',
                               return_value=ps) as _get_ports:
            result = self.agent._get_ofport_names('hoge')
        _get_ports.assert_called_once_with('hoge')
        self.assertEqual(set(names), result)
