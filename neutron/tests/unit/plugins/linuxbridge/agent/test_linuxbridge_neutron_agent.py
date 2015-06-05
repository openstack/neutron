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

import os

import mock
from oslo_config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.common import exceptions
from neutron.plugins.common import constants as p_const
from neutron.plugins.linuxbridge.agent import linuxbridge_neutron_agent
from neutron.plugins.linuxbridge.common import constants as lconst
from neutron.tests import base

LOCAL_IP = '192.168.0.33'
DEVICE_1 = 'tapabcdef01-12'


class FakeIpLinkCommand(object):
    def set_up(self):
        pass


class FakeIpDevice(object):
    def __init__(self):
        self.link = FakeIpLinkCommand()


class TestLinuxBridge(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxBridge, self).setUp()
        interface_mappings = {'physnet1': 'eth1'}

        with mock.patch.object(linuxbridge_neutron_agent.LinuxBridgeManager,
                               'get_interface_by_ip', return_value=None):
            self.linux_bridge = linuxbridge_neutron_agent.LinuxBridgeManager(
                interface_mappings)

    def test_ensure_physical_in_bridge_invalid(self):
        result = self.linux_bridge.ensure_physical_in_bridge('network_id',
                                                             p_const.TYPE_VLAN,
                                                             'physnetx',
                                                             7)
        self.assertFalse(result)

    def test_ensure_physical_in_bridge_flat(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_flat_bridge') as flat_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', p_const.TYPE_FLAT, 'physnet1', None)
        self.assertTrue(flat_bridge_func.called)

    def test_ensure_physical_in_bridge_vlan(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_vlan_bridge') as vlan_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', p_const.TYPE_VLAN, 'physnet1', 7)
        self.assertTrue(vlan_bridge_func.called)

    def test_ensure_physical_in_bridge_vxlan(self):
        self.linux_bridge.vxlan_mode = lconst.VXLAN_UCAST
        with mock.patch.object(self.linux_bridge,
                               'ensure_vxlan_bridge') as vxlan_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', 'vxlan', 'physnet1', 7)
        self.assertTrue(vxlan_bridge_func.called)


class TestLinuxBridgeAgent(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxBridgeAgent, self).setUp()
        # disable setting up periodic state reporting
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        self.get_devices_p = mock.patch.object(ip_lib.IPWrapper, 'get_devices')
        self.get_devices = self.get_devices_p.start()
        self.get_devices.return_value = [ip_lib.IPDevice('eth77')]
        self.get_mac_p = mock.patch('neutron.agent.linux.utils.'
                                    'get_interface_mac')
        self.get_mac = self.get_mac_p.start()
        self.get_mac.return_value = '00:00:00:00:00:01'
        with mock.patch.object(linuxbridge_neutron_agent.LinuxBridgeManager,
                               'get_interface_by_ip', return_value=None):
            self.agent = linuxbridge_neutron_agent.LinuxBridgeNeutronAgentRPC(
                {}, 0, cfg.CONF.AGENT.quitting_rpc_timeout)
            with mock.patch.object(self.agent, "daemon_loop"):
                self.agent.start()

    def test_treat_devices_removed_with_existed_device(self):
        agent = self.agent
        devices = [DEVICE_1]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter") as fn_rdf:
            fn_udd.return_value = {'device': DEVICE_1,
                                   'exists': True}
            with mock.patch.object(linuxbridge_neutron_agent.LOG,
                                   'info') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(2, log.call_count)
                self.assertFalse(resync)
                self.assertTrue(fn_udd.called)
                self.assertTrue(fn_rdf.called)

    def test_treat_devices_removed_with_not_existed_device(self):
        agent = self.agent
        devices = [DEVICE_1]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter") as fn_rdf:
            fn_udd.return_value = {'device': DEVICE_1,
                                   'exists': False}
            with mock.patch.object(linuxbridge_neutron_agent.LOG,
                                   'debug') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(1, log.call_count)
                self.assertFalse(resync)
                self.assertTrue(fn_udd.called)
                self.assertTrue(fn_rdf.called)

    def test_treat_devices_removed_failed(self):
        agent = self.agent
        devices = [DEVICE_1]
        with mock.patch.object(agent.plugin_rpc,
                               "update_device_down") as fn_udd,\
                mock.patch.object(agent.sg_agent,
                                  "remove_devices_filter") as fn_rdf:
            fn_udd.side_effect = Exception()
            with mock.patch.object(linuxbridge_neutron_agent.LOG,
                                   'debug') as log:
                resync = agent.treat_devices_removed(devices)
                self.assertEqual(2, log.call_count)
                self.assertTrue(resync)
                self.assertTrue(fn_udd.called)
                self.assertTrue(fn_rdf.called)

    def _test_scan_devices(self, previous, updated,
                           fake_current, expected, sync):
        self.agent.br_mgr = mock.Mock()
        self.agent.br_mgr.get_tap_devices.return_value = fake_current

        self.agent.updated_devices = updated
        results = self.agent.scan_devices(previous, sync)
        self.assertEqual(expected, results)

    def test_scan_devices_no_changes(self):
        previous = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        fake_current = set([1, 2])
        updated = set()
        expected = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_added_removed(self):
        previous = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        fake_current = set([2, 3])
        updated = set()
        expected = {'current': set([2, 3]),
                    'updated': set(),
                    'added': set([3]),
                    'removed': set([1])}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_removed_retried_on_sync(self):
        previous = {'current': set([2, 3]),
                    'updated': set(),
                    'added': set(),
                    'removed': set([1])}
        fake_current = set([2, 3])
        updated = set()
        expected = {'current': set([2, 3]),
                    'updated': set(),
                    'added': set([2, 3]),
                    'removed': set([1])}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_scan_devices_vanished_removed_on_sync(self):
        previous = {'current': set([2, 3]),
                    'updated': set(),
                    'added': set(),
                    'removed': set([1])}
        # Device 2 disappeared.
        fake_current = set([3])
        updated = set()
        # Device 1 should be retried.
        expected = {'current': set([3]),
                    'updated': set(),
                    'added': set([3]),
                    'removed': set([1, 2])}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_scan_devices_updated(self):
        previous = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        fake_current = set([1, 2])
        updated = set([1])
        expected = {'current': set([1, 2]),
                    'updated': set([1]),
                    'added': set(),
                    'removed': set()}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_updated_non_existing(self):
        previous = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}
        fake_current = set([1, 2])
        updated = set([3])
        expected = {'current': set([1, 2]),
                    'updated': set(),
                    'added': set(),
                    'removed': set()}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=False)

    def test_scan_devices_updated_on_sync(self):
        previous = {'current': set([1, 2]),
                    'updated': set([1]),
                    'added': set(),
                    'removed': set()}
        fake_current = set([1, 2])
        updated = set([2])
        expected = {'current': set([1, 2]),
                    'updated': set([1, 2]),
                    'added': set([1, 2]),
                    'removed': set()}

        self._test_scan_devices(previous, updated, fake_current, expected,
                                sync=True)

    def test_process_network_devices(self):
        agent = self.agent
        device_info = {'current': set(),
                       'added': set(['tap3', 'tap4']),
                       'updated': set(['tap2', 'tap3']),
                       'removed': set(['tap1'])}
        agent.sg_agent.prepare_devices_filter = mock.Mock()
        agent.sg_agent.refresh_firewall = mock.Mock()
        agent.treat_devices_added_updated = mock.Mock(return_value=False)
        agent.treat_devices_removed = mock.Mock(return_value=False)

        agent.process_network_devices(device_info)

        agent.sg_agent.prepare_devices_filter.assert_called_with(
                set(['tap3', 'tap4']))
        self.assertTrue(agent.sg_agent.refresh_firewall.called)
        agent.treat_devices_added_updated.assert_called_with(set(['tap2',
                                                                  'tap3',
                                                                  'tap4']))
        agent.treat_devices_removed.assert_called_with(set(['tap1']))

    def test_treat_devices_added_updated_admin_state_up_true(self):
        agent = self.agent
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': True,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1'}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.br_mgr = mock.Mock()
        agent.br_mgr.add_interface.return_value = True
        resync_needed = agent.treat_devices_added_updated(set(['tap1']))

        self.assertFalse(resync_needed)
        agent.br_mgr.add_interface.assert_called_with('net123', 'vlan',
                                                      'physnet1', 100,
                                                      'port123')
        self.assertTrue(agent.plugin_rpc.update_device_up.called)

    def test_treat_devices_added_updated_admin_state_up_false(self):
        agent = self.agent
        mock_details = {'device': 'dev123',
                        'port_id': 'port123',
                        'network_id': 'net123',
                        'admin_state_up': False,
                        'network_type': 'vlan',
                        'segmentation_id': 100,
                        'physical_network': 'physnet1'}
        agent.plugin_rpc = mock.Mock()
        agent.plugin_rpc.get_devices_details_list.return_value = [mock_details]
        agent.remove_port_binding = mock.Mock()
        resync_needed = agent.treat_devices_added_updated(set(['tap1']))

        self.assertFalse(resync_needed)
        agent.remove_port_binding.assert_called_with('net123', 'port123')
        self.assertFalse(agent.plugin_rpc.update_device_up.called)

    def test_set_rpc_timeout(self):
        self.agent.stop()
        for rpc_client in (self.agent.plugin_rpc.client,
                           self.agent.sg_plugin_rpc.client,
                           self.agent.state_rpc.client):
            self.assertEqual(cfg.CONF.AGENT.quitting_rpc_timeout,
                             rpc_client.timeout)

    def test_set_rpc_timeout_no_value(self):
        self.agent.quitting_rpc_timeout = None
        with mock.patch.object(self.agent, 'set_rpc_timeout') as mock_set_rpc:
            self.agent.stop()
            self.assertFalse(mock_set_rpc.called)


class TestLinuxBridgeManager(base.BaseTestCase):
    def setUp(self):
        super(TestLinuxBridgeManager, self).setUp()
        self.interface_mappings = {'physnet1': 'eth1'}

        with mock.patch.object(linuxbridge_neutron_agent.LinuxBridgeManager,
                               'get_interface_by_ip', return_value=None):
            self.lbm = linuxbridge_neutron_agent.LinuxBridgeManager(
                self.interface_mappings)

    def test_interface_exists_on_bridge(self):
        with mock.patch.object(os, 'listdir') as listdir_fn:
            listdir_fn.return_value = ["abc"]
            self.assertTrue(
                self.lbm.interface_exists_on_bridge("br-int", "abc")
            )
            self.assertFalse(
                self.lbm.interface_exists_on_bridge("br-int", "abd")
            )

    def test_get_bridge_name(self):
        nw_id = "123456789101112"
        self.assertEqual(self.lbm.get_bridge_name(nw_id),
                         "brq" + nw_id[0:11])
        nw_id = ""
        self.assertEqual(self.lbm.get_bridge_name(nw_id),
                         "brq")

    def test_get_subinterface_name(self):
        self.assertEqual(self.lbm.get_subinterface_name("eth0", "0"),
                         "eth0.0")
        self.assertEqual(self.lbm.get_subinterface_name("eth0", ""),
                         "eth0.")

    def test_get_tap_device_name(self):
        if_id = "123456789101112"
        self.assertEqual(self.lbm.get_tap_device_name(if_id),
                         constants.TAP_DEVICE_PREFIX + if_id[0:11])
        if_id = ""
        self.assertEqual(self.lbm.get_tap_device_name(if_id),
                         constants.TAP_DEVICE_PREFIX)

    def test_get_vxlan_device_name(self):
        vn_id = p_const.MAX_VXLAN_VNI
        self.assertEqual(self.lbm.get_vxlan_device_name(vn_id),
                         "vxlan-" + str(vn_id))
        self.assertIsNone(self.lbm.get_vxlan_device_name(vn_id + 1))

    def test_get_all_neutron_bridges(self):
        br_list = ["br-int", "brq1", "brq2", "br-ex"]
        with mock.patch.object(os, 'listdir') as listdir_fn:
            listdir_fn.return_value = br_list
            self.assertEqual(self.lbm.get_all_neutron_bridges(),
                             br_list[1:3])
            self.assertTrue(listdir_fn.called)

    def test_get_interfaces_on_bridge(self):
        with mock.patch.object(utils, 'execute'),\
                mock.patch.object(os, 'listdir') as listdir_fn,\
                mock.patch.object(ip_lib, 'device_exists', return_value=True):
            listdir_fn.return_value = ["qbr1"]
            self.assertEqual(self.lbm.get_interfaces_on_bridge("br0"),
                             ["qbr1"])

    def test_get_interfaces_on_bridge_not_existing(self):
        with mock.patch.object(ip_lib, 'device_exists', return_value=False):
            self.assertEqual([], self.lbm.get_interfaces_on_bridge("br0"))

    def test_get_tap_devices_count(self):
        with mock.patch.object(os, 'listdir') as listdir_fn:
            listdir_fn.return_value = ['tap2101', 'eth0.100', 'vxlan-1000']
            self.assertEqual(self.lbm.get_tap_devices_count('br0'), 1)
            listdir_fn.side_effect = OSError()
            self.assertEqual(self.lbm.get_tap_devices_count('br0'), 0)

    def test_get_interface_by_ip(self):
        with mock.patch.object(ip_lib.IPWrapper, 'get_devices') as get_dev_fn,\
                mock.patch.object(ip_lib.IpAddrCommand, 'list') as ip_list_fn:
            device = mock.Mock()
            device.name = 'dev_name'
            get_dev_fn.return_value = [device]
            ip_list_fn.returnvalue = mock.Mock()
            self.assertEqual(self.lbm.get_interface_by_ip(LOCAL_IP),
                             'dev_name')

    def test_get_bridge_for_tap_device(self):
        with mock.patch.object(self.lbm,
                               "get_all_neutron_bridges") as get_all_qbr_fn,\
                mock.patch.object(self.lbm,
                                  "get_interfaces_on_bridge") as get_if_fn:
            get_all_qbr_fn.return_value = ["br-int", "br-ex"]
            get_if_fn.return_value = ["tap1", "tap2", "tap3"]
            self.assertEqual(self.lbm.get_bridge_for_tap_device("tap1"),
                             "br-int")
            self.assertIsNone(self.lbm.get_bridge_for_tap_device("tap4"))

    def test_is_device_on_bridge(self):
        self.assertTrue(not self.lbm.is_device_on_bridge(""))
        with mock.patch.object(os.path, 'exists') as exists_fn:
            exists_fn.return_value = True
            self.assertTrue(self.lbm.is_device_on_bridge("tap1"))
            exists_fn.assert_called_with(
                "/sys/class/net/tap1/brport"
            )

    def test_get_interface_details(self):
        with mock.patch.object(ip_lib.IpAddrCommand, 'list') as list_fn,\
                mock.patch.object(ip_lib.IpRouteCommand,
                                  'get_gateway') as getgw_fn:
            gwdict = dict(gateway='1.1.1.1')
            getgw_fn.return_value = gwdict
            ipdict = dict(cidr='1.1.1.1/24',
                          broadcast='1.1.1.255',
                          scope='global',
                          ip_version=4,
                          dynamic=False)
            list_fn.return_value = ipdict
            ret = self.lbm.get_interface_details("eth0")

            self.assertTrue(list_fn.called)
            self.assertTrue(getgw_fn.called)
            self.assertEqual(ret, (ipdict, gwdict))

    def test_ensure_flat_bridge(self):
        with mock.patch.object(ip_lib.IpAddrCommand, 'list') as list_fn,\
                mock.patch.object(ip_lib.IpRouteCommand,
                                  'get_gateway') as getgw_fn:
            gwdict = dict(gateway='1.1.1.1')
            getgw_fn.return_value = gwdict
            ipdict = dict(cidr='1.1.1.1/24',
                          broadcast='1.1.1.255',
                          scope='global',
                          ip_version=4,
                          dynamic=False)
            list_fn.return_value = ipdict
            with mock.patch.object(self.lbm, 'ensure_bridge') as ens:
                self.assertEqual(
                    self.lbm.ensure_flat_bridge("123", "eth0"),
                    "eth0"
                )
                self.assertTrue(list_fn.called)
                self.assertTrue(getgw_fn.called)
                ens.assert_called_once_with("brq123", "eth0",
                                            ipdict, gwdict)

    def test_ensure_vlan_bridge(self):
        with mock.patch.object(self.lbm, 'ensure_vlan') as ens_vl_fn,\
                mock.patch.object(self.lbm, 'ensure_bridge') as ens,\
                mock.patch.object(self.lbm,
                                  'get_interface_details') as get_int_det_fn:
            ens_vl_fn.return_value = "eth0.1"
            get_int_det_fn.return_value = (None, None)
            self.assertEqual(self.lbm.ensure_vlan_bridge("123", "eth0", "1"),
                             "eth0.1")
            ens.assert_called_with("brq123", "eth0.1", None, None)

            get_int_det_fn.return_value = ("ips", "gateway")
            self.assertEqual(self.lbm.ensure_vlan_bridge("123", "eth0", "1"),
                             "eth0.1")
            ens.assert_called_with("brq123", "eth0.1", "ips", "gateway")

    def test_ensure_local_bridge(self):
        with mock.patch.object(self.lbm, 'ensure_bridge') as ens_fn:
            self.lbm.ensure_local_bridge("54321")
            ens_fn.assert_called_once_with("brq54321")

    def test_ensure_vlan(self):
        with mock.patch.object(ip_lib, 'device_exists') as de_fn:
            de_fn.return_value = True
            self.assertEqual(self.lbm.ensure_vlan("eth0", "1"), "eth0.1")
            de_fn.return_value = False
            with mock.patch.object(utils, 'execute') as exec_fn:
                exec_fn.return_value = False
                self.assertEqual(self.lbm.ensure_vlan("eth0", "1"), "eth0.1")
                # FIXME(kevinbenton): validate the params to the exec_fn calls
                self.assertEqual(exec_fn.call_count, 2)
                exec_fn.return_value = True
                self.assertIsNone(self.lbm.ensure_vlan("eth0", "1"))
                self.assertEqual(exec_fn.call_count, 3)

    def test_ensure_vxlan(self):
        seg_id = "12345678"
        self.lbm.local_int = 'eth0'
        self.lbm.vxlan_mode = lconst.VXLAN_MCAST
        with mock.patch.object(ip_lib, 'device_exists') as de_fn:
            de_fn.return_value = True
            self.assertEqual(self.lbm.ensure_vxlan(seg_id), "vxlan-" + seg_id)
            de_fn.return_value = False
            with mock.patch.object(self.lbm.ip,
                                   'add_vxlan') as add_vxlan_fn:
                add_vxlan_fn.return_value = FakeIpDevice()
                self.assertEqual(self.lbm.ensure_vxlan(seg_id),
                                 "vxlan-" + seg_id)
                add_vxlan_fn.assert_called_with("vxlan-" + seg_id, seg_id,
                                                group="224.0.0.1",
                                                dev=self.lbm.local_int)
                cfg.CONF.set_override('l2_population', 'True', 'VXLAN')
                self.assertEqual(self.lbm.ensure_vxlan(seg_id),
                                 "vxlan-" + seg_id)
                add_vxlan_fn.assert_called_with("vxlan-" + seg_id, seg_id,
                                                group="224.0.0.1",
                                                dev=self.lbm.local_int,
                                                proxy=True)

    def test_update_interface_ip_details(self):
        gwdict = dict(gateway='1.1.1.1',
                      metric=50)
        ipdict = dict(cidr='1.1.1.1/24',
                      broadcast='1.1.1.255',
                      scope='global',
                      ip_version=4,
                      dynamic=False)
        with mock.patch.object(ip_lib.IpAddrCommand, 'add') as add_fn,\
                mock.patch.object(ip_lib.IpAddrCommand, 'delete') as del_fn:
            self.lbm.update_interface_ip_details("br0", "eth0",
                                                 [ipdict], None)
            self.assertTrue(add_fn.called)
            self.assertTrue(del_fn.called)

        with mock.patch.object(ip_lib.IpRouteCommand,
                               'add_gateway') as addgw_fn,\
                mock.patch.object(ip_lib.IpRouteCommand,
                                  'delete_gateway') as delgw_fn:
            self.lbm.update_interface_ip_details("br0", "eth0",
                                                 None, gwdict)
            self.assertTrue(addgw_fn.called)
            self.assertTrue(delgw_fn.called)

    def test_bridge_exists_and_ensure_up(self):
        ip_lib_mock = mock.Mock()
        with mock.patch.object(ip_lib, 'IPDevice', return_value=ip_lib_mock):
            # device exists
            self.assertTrue(self.lbm._bridge_exists_and_ensure_up("br0"))
            self.assertTrue(ip_lib_mock.link.set_up.called)
            # device doesn't exists
            ip_lib_mock.link.set_up.side_effect = RuntimeError
            self.assertFalse(self.lbm._bridge_exists_and_ensure_up("br0"))

    def test_ensure_bridge(self):
        with mock.patch.object(self.lbm,
                               '_bridge_exists_and_ensure_up') as de_fn,\
                mock.patch.object(utils, 'execute') as exec_fn,\
                mock.patch.object(self.lbm,
                                  'update_interface_ip_details') as upd_fn,\
                mock.patch.object(self.lbm,
                                  'interface_exists_on_bridge') as ie_fn,\
                mock.patch.object(self.lbm, 'is_device_on_bridge'),\
                mock.patch.object(self.lbm,
                                  'get_bridge_for_tap_device') as get_if_br_fn:
            de_fn.return_value = False
            exec_fn.return_value = False
            self.assertEqual(self.lbm.ensure_bridge("br0", None), "br0")
            ie_fn.return_Value = False
            self.lbm.ensure_bridge("br0", "eth0")
            upd_fn.assert_called_with("br0", "eth0", None, None)
            ie_fn.assert_called_with("br0", "eth0")

            self.lbm.ensure_bridge("br0", "eth0", "ips", "gateway")
            upd_fn.assert_called_with("br0", "eth0", "ips", "gateway")
            ie_fn.assert_called_with("br0", "eth0")

            exec_fn.side_effect = Exception()
            de_fn.return_value = True
            self.lbm.ensure_bridge("br0", "eth0")
            ie_fn.assert_called_with("br0", "eth0")

            exec_fn.reset_mock()
            exec_fn.side_effect = None
            de_fn.return_value = True
            ie_fn.return_value = False
            get_if_br_fn.return_value = "br1"
            self.lbm.ensure_bridge("br0", "eth0")
            expected = [
                mock.call(['brctl', 'delif', 'br1', 'eth0'],
                          run_as_root=True),
                mock.call(['brctl', 'addif', 'br0', 'eth0'],
                          run_as_root=True),
            ]
            exec_fn.assert_has_calls(expected)

    def test_ensure_physical_in_bridge(self):
        self.assertFalse(
            self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_VLAN,
                                               "phys", "1")
        )
        with mock.patch.object(self.lbm, "ensure_flat_bridge") as flbr_fn:
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_FLAT,
                                                   "physnet1", None)
            )
            self.assertTrue(flbr_fn.called)
        with mock.patch.object(self.lbm, "ensure_vlan_bridge") as vlbr_fn:
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_VLAN,
                                                   "physnet1", "1")
            )
            self.assertTrue(vlbr_fn.called)

        with mock.patch.object(self.lbm, "ensure_vxlan_bridge") as vlbr_fn:
            self.lbm.vxlan_mode = lconst.VXLAN_MCAST
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", p_const.TYPE_VXLAN,
                                                   "physnet1", "1")
            )
            self.assertTrue(vlbr_fn.called)

    def test_add_tap_interface(self):
        with mock.patch.object(ip_lib, "device_exists") as de_fn:
            de_fn.return_value = False
            self.assertFalse(
                self.lbm.add_tap_interface("123", p_const.TYPE_VLAN,
                                           "physnet1", "1", "tap1")
            )

            de_fn.return_value = True
            with mock.patch.object(self.lbm, "ensure_local_bridge") as en_fn,\
                    mock.patch.object(utils, "execute") as exec_fn,\
                    mock.patch.object(self.lbm,
                                      "get_bridge_for_tap_device") as get_br:
                exec_fn.return_value = False
                get_br.return_value = True
                self.assertTrue(self.lbm.add_tap_interface("123",
                                                           p_const.TYPE_LOCAL,
                                                           "physnet1", None,
                                                           "tap1"))
                en_fn.assert_called_with("123")

                get_br.return_value = False
                exec_fn.return_value = True
                self.assertFalse(self.lbm.add_tap_interface("123",
                                                            p_const.TYPE_LOCAL,
                                                            "physnet1", None,
                                                            "tap1"))

            with mock.patch.object(self.lbm,
                                   "ensure_physical_in_bridge") as ens_fn,\
                    mock.patch.object(self.lbm,
                                      "ensure_tap_mtu") as en_mtu_fn,\
                    mock.patch.object(self.lbm,
                                      "get_bridge_for_tap_device") as get_br:
                ens_fn.return_value = False
                self.assertFalse(self.lbm.add_tap_interface("123",
                                                            p_const.TYPE_VLAN,
                                                            "physnet1", "1",
                                                            "tap1"))

                ens_fn.return_value = "eth0.1"
                get_br.return_value = "brq123"
                self.lbm.add_tap_interface("123", p_const.TYPE_VLAN,
                                           "physnet1", "1", "tap1")
                en_mtu_fn.assert_called_once_with("tap1", "eth0.1")

    def test_add_interface(self):
        with mock.patch.object(self.lbm, "add_tap_interface") as add_tap:
            self.lbm.add_interface("123", p_const.TYPE_VLAN, "physnet-1",
                                   "1", "234")
            add_tap.assert_called_with("123", p_const.TYPE_VLAN, "physnet-1",
                                       "1", "tap234")

    def test_delete_vlan_bridge(self):
        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(self.lbm,
                                  "get_interfaces_on_bridge") as getif_fn,\
                mock.patch.object(self.lbm, "remove_interface"),\
                mock.patch.object(self.lbm,
                                  "get_interface_details") as if_det_fn,\
                mock.patch.object(self.lbm,
                                  "update_interface_ip_details") as updif_fn,\
                mock.patch.object(self.lbm, "delete_vxlan") as del_vxlan,\
                mock.patch.object(utils, "execute") as exec_fn:
            de_fn.return_value = False
            self.lbm.delete_vlan_bridge("br0")
            self.assertFalse(getif_fn.called)

            de_fn.return_value = True
            getif_fn.return_value = ["eth0", "eth1", "vxlan-1002"]
            if_det_fn.return_value = ("ips", "gateway")
            exec_fn.return_value = False
            self.lbm.delete_vlan_bridge("br0")
            updif_fn.assert_called_with("eth1", "br0", "ips", "gateway")
            del_vxlan.assert_called_with("vxlan-1002")

    def test_delete_vlan_bridge_with_ip(self):
        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(self.lbm,
                                  "get_interfaces_on_bridge") as getif_fn,\
                mock.patch.object(self.lbm, "remove_interface"),\
                mock.patch.object(self.lbm,
                                  "get_interface_details") as if_det_fn,\
                mock.patch.object(self.lbm,
                                  "update_interface_ip_details") as updif_fn,\
                mock.patch.object(self.lbm, "delete_vlan") as del_vlan,\
                mock.patch.object(utils, "execute") as exec_fn:
            de_fn.return_value = True
            getif_fn.return_value = ["eth0", "eth1.1"]
            if_det_fn.return_value = ("ips", "gateway")
            exec_fn.return_value = False
            self.lbm.delete_vlan_bridge("br0")
            updif_fn.assert_called_with("eth1.1", "br0", "ips", "gateway")
            self.assertFalse(del_vlan.called)

    def test_delete_vlan_bridge_no_ip(self):
        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(self.lbm,
                                  "get_interfaces_on_bridge") as getif_fn,\
                mock.patch.object(self.lbm, "remove_interface"),\
                mock.patch.object(self.lbm,
                                  "get_interface_details") as if_det_fn,\
                mock.patch.object(self.lbm,
                                  "update_interface_ip_details") as updif_fn,\
                mock.patch.object(self.lbm, "delete_vlan") as del_vlan,\
                mock.patch.object(utils, "execute") as exec_fn:
            de_fn.return_value = True
            getif_fn.return_value = ["eth0", "eth1.1"]
            exec_fn.return_value = False
            if_det_fn.return_value = ([], None)
            self.lbm.delete_vlan_bridge("br0")
            del_vlan.assert_called_with("eth1.1")
            self.assertFalse(updif_fn.called)

    def test_delete_vxlan_bridge_no_int_mappings(self):
        interface_mappings = {}
        with mock.patch.object(linuxbridge_neutron_agent.LinuxBridgeManager,
                               'get_interface_by_ip', return_value=None):
            lbm = linuxbridge_neutron_agent.LinuxBridgeManager(
                interface_mappings)

        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(lbm,
                                  "get_interfaces_on_bridge") as getif_fn,\
                mock.patch.object(lbm, "remove_interface"),\
                mock.patch.object(lbm, "delete_vxlan") as del_vxlan,\
                mock.patch.object(utils, "execute") as exec_fn:
            de_fn.return_value = False
            lbm.delete_vlan_bridge("br0")
            self.assertFalse(getif_fn.called)

            de_fn.return_value = True
            getif_fn.return_value = ["vxlan-1002"]
            exec_fn.return_value = False
            lbm.delete_vlan_bridge("br0")
            del_vxlan.assert_called_with("vxlan-1002")

    def test_remove_empty_bridges(self):
        self.lbm.network_map = {'net1': mock.Mock(), 'net2': mock.Mock()}

        def tap_count_side_effect(*args):
            return 0 if args[0] == 'brqnet1' else 1

        with mock.patch.object(self.lbm, "delete_vlan_bridge") as del_br_fn,\
                mock.patch.object(self.lbm,
                                  "get_tap_devices_count",
                                  side_effect=tap_count_side_effect):
            self.lbm.remove_empty_bridges()
            del_br_fn.assert_called_once_with('brqnet1')

    def test_remove_interface(self):
        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(self.lbm,
                                  "is_device_on_bridge") as isdev_fn,\
                mock.patch.object(utils, "execute") as exec_fn:
            de_fn.return_value = False
            self.assertFalse(self.lbm.remove_interface("br0", "eth0"))
            self.assertFalse(isdev_fn.called)

            de_fn.return_value = True
            isdev_fn.return_value = False
            self.assertTrue(self.lbm.remove_interface("br0", "eth0"))

            isdev_fn.return_value = True
            exec_fn.return_value = True
            self.assertFalse(self.lbm.remove_interface("br0", "eth0"))

            exec_fn.return_value = False
            self.assertTrue(self.lbm.remove_interface("br0", "eth0"))

    def test_delete_vlan(self):
        with mock.patch.object(ip_lib, "device_exists") as de_fn,\
                mock.patch.object(utils, "execute") as exec_fn:
            de_fn.return_value = False
            self.lbm.delete_vlan("eth1.1")
            self.assertFalse(exec_fn.called)

            de_fn.return_value = True
            exec_fn.return_value = False
            self.lbm.delete_vlan("eth1.1")
            self.assertTrue(exec_fn.called)

    def _check_vxlan_support(self, expected, vxlan_ucast_supported,
                             vxlan_mcast_supported):
        with mock.patch.object(self.lbm,
                               'vxlan_ucast_supported',
                               return_value=vxlan_ucast_supported),\
                mock.patch.object(self.lbm,
                                  'vxlan_mcast_supported',
                                  return_value=vxlan_mcast_supported):
            if expected == lconst.VXLAN_NONE:
                self.assertRaises(exceptions.VxlanNetworkUnsupported,
                                  self.lbm.check_vxlan_support)
                self.assertEqual(expected, self.lbm.vxlan_mode)
            else:
                self.lbm.check_vxlan_support()
                self.assertEqual(expected, self.lbm.vxlan_mode)

    def test_check_vxlan_support(self):
        self._check_vxlan_support(expected=lconst.VXLAN_UCAST,
                                  vxlan_ucast_supported=True,
                                  vxlan_mcast_supported=True)
        self._check_vxlan_support(expected=lconst.VXLAN_MCAST,
                                  vxlan_ucast_supported=False,
                                  vxlan_mcast_supported=True)

        self._check_vxlan_support(expected=lconst.VXLAN_NONE,
                                  vxlan_ucast_supported=False,
                                  vxlan_mcast_supported=False)
        self._check_vxlan_support(expected=lconst.VXLAN_NONE,
                                  vxlan_ucast_supported=False,
                                  vxlan_mcast_supported=False)

    def _check_vxlan_ucast_supported(
            self, expected, l2_population, iproute_arg_supported, fdb_append):
        cfg.CONF.set_override('l2_population', l2_population, 'VXLAN')
        with mock.patch.object(ip_lib, 'device_exists', return_value=False),\
                mock.patch.object(self.lbm,
                                  'delete_vxlan',
                                  return_value=None),\
                mock.patch.object(self.lbm,
                                  'ensure_vxlan',
                                  return_value=None),\
                mock.patch.object(
                    utils,
                    'execute',
                    side_effect=None if fdb_append else RuntimeError()),\
                mock.patch.object(ip_lib,
                                  'iproute_arg_supported',
                                  return_value=iproute_arg_supported):
            self.assertEqual(expected, self.lbm.vxlan_ucast_supported())

    def test_vxlan_ucast_supported(self):
        self._check_vxlan_ucast_supported(
            expected=False,
            l2_population=False, iproute_arg_supported=True, fdb_append=True)
        self._check_vxlan_ucast_supported(
            expected=False,
            l2_population=True, iproute_arg_supported=False, fdb_append=True)
        self._check_vxlan_ucast_supported(
            expected=False,
            l2_population=True, iproute_arg_supported=True, fdb_append=False)
        self._check_vxlan_ucast_supported(
            expected=True,
            l2_population=True, iproute_arg_supported=True, fdb_append=True)

    def _check_vxlan_mcast_supported(
            self, expected, vxlan_group, iproute_arg_supported):
        cfg.CONF.set_override('vxlan_group', vxlan_group, 'VXLAN')
        with mock.patch.object(
                ip_lib, 'iproute_arg_supported',
                return_value=iproute_arg_supported):
            self.assertEqual(expected, self.lbm.vxlan_mcast_supported())

    def test_vxlan_mcast_supported(self):
        self._check_vxlan_mcast_supported(
            expected=False,
            vxlan_group='',
            iproute_arg_supported=True)
        self._check_vxlan_mcast_supported(
            expected=False,
            vxlan_group='224.0.0.1',
            iproute_arg_supported=False)
        self._check_vxlan_mcast_supported(
            expected=True,
            vxlan_group='224.0.0.1',
            iproute_arg_supported=True)


class TestLinuxBridgeRpcCallbacks(base.BaseTestCase):
    def setUp(self):
        cfg.CONF.set_override('local_ip', LOCAL_IP, 'VXLAN')
        super(TestLinuxBridgeRpcCallbacks, self).setUp()

        class FakeLBAgent(object):
            def __init__(self):
                self.agent_id = 1
                with mock.patch.object(
                        linuxbridge_neutron_agent.LinuxBridgeManager,
                        'get_interface_by_ip', return_value=None):
                    self.br_mgr = (linuxbridge_neutron_agent.
                                   LinuxBridgeManager({'physnet1': 'eth1'}))

                self.br_mgr.vxlan_mode = lconst.VXLAN_UCAST
                segment = mock.Mock()
                segment.network_type = 'vxlan'
                segment.segmentation_id = 1
                self.br_mgr.network_map['net_id'] = segment

        self.lb_rpc = linuxbridge_neutron_agent.LinuxBridgeRpcCallbacks(
            object(),
            FakeLBAgent(),
            object()
        )

    def test_network_delete(self):
        with mock.patch.object(self.lb_rpc.agent.br_mgr,
                               "get_bridge_name") as get_br_fn,\
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "delete_vlan_bridge") as del_fn:
            get_br_fn.return_value = "br0"
            self.lb_rpc.network_delete("anycontext", network_id="123")
            get_br_fn.assert_called_with("123")
            del_fn.assert_called_with("br0")

    def test_fdb_add(self):
        fdb_entries = {'net_id':
                       {'ports':
                        {'agent_ip': [constants.FLOODING_ENTRY,
                                      ['port_mac', 'port_ip']]},
                        'network_type': 'vxlan',
                        'segment_id': 1}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn:
            self.lb_rpc.fdb_add(None, fdb_entries)

            expected = [
                mock.call(['bridge', 'fdb', 'show', 'dev', 'vxlan-1'],
                          run_as_root=True),
                mock.call(['bridge', 'fdb', 'add',
                           constants.FLOODING_ENTRY[0],
                           'dev', 'vxlan-1', 'dst', 'agent_ip'],
                          run_as_root=True,
                          check_exit_code=False),
                mock.call(['ip', 'neigh', 'replace', 'port_ip', 'lladdr',
                           'port_mac', 'dev', 'vxlan-1', 'nud', 'permanent'],
                          run_as_root=True,
                          check_exit_code=False),
                mock.call(['bridge', 'fdb', 'replace', 'port_mac', 'dev',
                           'vxlan-1', 'dst', 'agent_ip'],
                          run_as_root=True,
                          check_exit_code=False),
            ]
            execute_fn.assert_has_calls(expected)

    def test_fdb_ignore(self):
        fdb_entries = {'net_id':
                       {'ports':
                        {LOCAL_IP: [constants.FLOODING_ENTRY,
                                    ['port_mac', 'port_ip']]},
                        'network_type': 'vxlan',
                        'segment_id': 1}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn:
            self.lb_rpc.fdb_add(None, fdb_entries)
            self.lb_rpc.fdb_remove(None, fdb_entries)

            self.assertFalse(execute_fn.called)

        fdb_entries = {'other_net_id':
                       {'ports':
                        {'192.168.0.67': [constants.FLOODING_ENTRY,
                                          ['port_mac', 'port_ip']]},
                        'network_type': 'vxlan',
                        'segment_id': 1}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn:
            self.lb_rpc.fdb_add(None, fdb_entries)
            self.lb_rpc.fdb_remove(None, fdb_entries)

            self.assertFalse(execute_fn.called)

    def test_fdb_remove(self):
        fdb_entries = {'net_id':
                       {'ports':
                        {'agent_ip': [constants.FLOODING_ENTRY,
                                      ['port_mac', 'port_ip']]},
                        'network_type': 'vxlan',
                        'segment_id': 1}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn:
            self.lb_rpc.fdb_remove(None, fdb_entries)

            expected = [
                mock.call(['bridge', 'fdb', 'del',
                           constants.FLOODING_ENTRY[0],
                           'dev', 'vxlan-1', 'dst', 'agent_ip'],
                          run_as_root=True,
                          check_exit_code=False),
                mock.call(['ip', 'neigh', 'del', 'port_ip', 'lladdr',
                           'port_mac', 'dev', 'vxlan-1'],
                          run_as_root=True,
                          check_exit_code=False),
                mock.call(['bridge', 'fdb', 'del', 'port_mac',
                           'dev', 'vxlan-1', 'dst', 'agent_ip'],
                          run_as_root=True,
                          check_exit_code=False),
            ]
            execute_fn.assert_has_calls(expected)

    def test_fdb_update_chg_ip(self):
        fdb_entries = {'chg_ip':
                       {'net_id':
                        {'agent_ip':
                         {'before': [['port_mac', 'port_ip_1']],
                          'after': [['port_mac', 'port_ip_2']]}}}}

        with mock.patch.object(utils, 'execute',
                               return_value='') as execute_fn:
            self.lb_rpc.fdb_update(None, fdb_entries)

            expected = [
                mock.call(['ip', 'neigh', 'replace', 'port_ip_2', 'lladdr',
                           'port_mac', 'dev', 'vxlan-1', 'nud', 'permanent'],
                          run_as_root=True,
                          check_exit_code=False),
                mock.call(['ip', 'neigh', 'del', 'port_ip_1', 'lladdr',
                           'port_mac', 'dev', 'vxlan-1'],
                          run_as_root=True,
                          check_exit_code=False)
            ]
            execute_fn.assert_has_calls(expected)

    def test_fdb_update_chg_ip_empty_lists(self):
        fdb_entries = {'chg_ip': {'net_id': {'agent_ip': {}}}}
        self.lb_rpc.fdb_update(None, fdb_entries)
