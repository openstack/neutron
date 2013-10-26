# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import contextlib
import os

import mock
from oslo.config import cfg
import testtools

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.openstack.common.rpc import common as rpc_common
from neutron.plugins.linuxbridge.agent import linuxbridge_neutron_agent
from neutron.plugins.linuxbridge.common import constants as lconst
from neutron.tests import base

LOCAL_IP = '192.168.0.33'


class FakeIpLinkCommand(object):
    def set_up(self):
        pass


class FakeIpDevice(object):
    def __init__(self):
        self.link = FakeIpLinkCommand()


class TestLinuxBridge(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxBridge, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        interface_mappings = {'physnet1': 'eth1'}
        root_helper = cfg.CONF.AGENT.root_helper

        self.linux_bridge = linuxbridge_neutron_agent.LinuxBridgeManager(
            interface_mappings, root_helper)

    def test_ensure_physical_in_bridge_invalid(self):
        result = self.linux_bridge.ensure_physical_in_bridge('network_id',
                                                             lconst.TYPE_VLAN,
                                                             'physnetx',
                                                             7)
        self.assertFalse(result)

    def test_ensure_physical_in_bridge_flat(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_flat_bridge') as flat_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', lconst.TYPE_FLAT, 'physnet1', None)
        self.assertTrue(flat_bridge_func.called)

    def test_ensure_physical_in_bridge_vlan(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_vlan_bridge') as vlan_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', lconst.TYPE_VLAN, 'physnet1', 7)
        self.assertTrue(vlan_bridge_func.called)

    def test_ensure_physical_in_bridge_vxlan(self):
        self.linux_bridge.vxlan_mode = lconst.VXLAN_UCAST
        with mock.patch.object(self.linux_bridge,
                               'ensure_vxlan_bridge') as vxlan_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', 'vxlan', 'physnet1', 7)
        self.assertTrue(vxlan_bridge_func.called)


class TestLinuxBridgeAgent(base.BaseTestCase):

    LINK_SAMPLE = [
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue \\'
        'state UNKNOWN \\'
        'link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00',
        '2: eth77: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 \\'
        'qdisc mq state UP qlen 1000\    link/ether \\'
        'cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff']

    def setUp(self):
        super(TestLinuxBridgeAgent, self).setUp()
        cfg.CONF.set_override('rpc_backend',
                              'neutron.openstack.common.rpc.impl_fake')
        self.execute_p = mock.patch.object(ip_lib.IPWrapper, '_execute')
        self.execute = self.execute_p.start()
        self.addCleanup(self.execute_p.stop)
        self.execute.return_value = '\n'.join(self.LINK_SAMPLE)
        self.get_mac_p = mock.patch('neutron.agent.linux.utils.'
                                    'get_interface_mac')
        self.get_mac = self.get_mac_p.start()
        self.addCleanup(self.get_mac_p.stop)
        self.get_mac.return_value = '00:00:00:00:00:01'

    def test_update_devices_failed(self):
        agent = linuxbridge_neutron_agent.LinuxBridgeNeutronAgentRPC({},
                                                                     0,
                                                                     None)
        raise_exception = [0]

        def info_mock(msg):
            if raise_exception[0] < 2:
                raise_exception[0] += 1
            else:
                raise RuntimeError()
        with mock.patch.object(agent.br_mgr,
                               "update_devices") as update_devices:
            update_devices.side_effect = RuntimeError
            with mock.patch.object(linuxbridge_neutron_agent.LOG,
                                   'info') as log:
                log.side_effect = info_mock
                with testtools.ExpectedException(RuntimeError):
                    agent.daemon_loop()
                self.assertEqual(3, log.call_count)

    def test_process_network_devices_failed(self):
        device_info = {'current': [1, 2, 3]}
        agent = linuxbridge_neutron_agent.LinuxBridgeNeutronAgentRPC({},
                                                                     0,
                                                                     None)
        raise_exception = [0]

        def info_mock(msg):
            if raise_exception[0] < 2:
                raise_exception[0] += 1
            else:
                raise RuntimeError()

        with mock.patch.object(agent.br_mgr,
                               "update_devices") as update_devices:
            update_devices.side_effect = device_info
            with contextlib.nested(
                mock.patch.object(linuxbridge_neutron_agent.LOG, 'info'),
                mock.patch.object(agent, 'process_network_devices')
            ) as (log, process_network_devices):
                log.side_effect = info_mock
                process_network_devices.side_effect = RuntimeError
                with testtools.ExpectedException(RuntimeError):
                    agent.daemon_loop()
                self.assertEqual(3, log.call_count)


class TestLinuxBridgeManager(base.BaseTestCase):
    def setUp(self):
        super(TestLinuxBridgeManager, self).setUp()
        self.interface_mappings = {'physnet1': 'eth1'}
        self.root_helper = cfg.CONF.AGENT.root_helper

        self.lbm = linuxbridge_neutron_agent.LinuxBridgeManager(
            self.interface_mappings, self.root_helper)

    def test_device_exists(self):
        with mock.patch.object(utils, 'execute') as execute_fn:
            self.assertTrue(self.lbm.device_exists("eth0"))
            execute_fn.side_effect = RuntimeError()
            self.assertFalse(self.lbm.device_exists("eth0"))

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
                         "tap" + if_id[0:11])
        if_id = ""
        self.assertEqual(self.lbm.get_tap_device_name(if_id),
                         "tap")

    def test_get_vxlan_device_name(self):
        vn_id = constants.MAX_VXLAN_VNI
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
        with contextlib.nested(
            mock.patch.object(utils, 'execute'),
            mock.patch.object(os, 'listdir')
        ) as (exec_fn, listdir_fn):
            listdir_fn.return_value = ["qbr1"]
            self.assertEqual(self.lbm.get_interfaces_on_bridge("br0"),
                             ["qbr1"])

    def test_get_tap_devices_count(self):
        with mock.patch.object(os, 'listdir') as listdir_fn:
            listdir_fn.return_value = ['tap2101', 'eth0.100', 'vxlan-1000']
            self.assertEqual(self.lbm.get_tap_devices_count('br0'), 1)
            listdir_fn.side_effect = OSError()
            self.assertEqual(self.lbm.get_tap_devices_count('br0'), 0)

    def test_get_interface_by_ip(self):
        with contextlib.nested(
            mock.patch.object(ip_lib.IPWrapper, 'get_devices'),
            mock.patch.object(ip_lib.IpAddrCommand, 'list')
        ) as (get_dev_fn, ip_list_fn):
            device = mock.Mock()
            device.name = 'dev_name'
            get_dev_fn.return_value = [device]
            ip_list_fn.returnvalue = mock.Mock()
            self.assertEqual(self.lbm.get_interface_by_ip(LOCAL_IP),
                             'dev_name')

    def test_get_bridge_for_tap_device(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, "get_all_neutron_bridges"),
            mock.patch.object(self.lbm, "get_interfaces_on_bridge")
        ) as (get_all_qbr_fn, get_if_fn):
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
                "/sys/devices/virtual/net/tap1/brport"
            )

    def test_get_interface_details(self):
        with contextlib.nested(
            mock.patch.object(ip_lib.IpAddrCommand, 'list'),
            mock.patch.object(ip_lib.IpRouteCommand, 'get_gateway')
        ) as (list_fn, getgw_fn):
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
        with contextlib.nested(
            mock.patch.object(ip_lib.IpAddrCommand, 'list'),
            mock.patch.object(ip_lib.IpRouteCommand, 'get_gateway')
        ) as (list_fn, getgw_fn):
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
        with contextlib.nested(
            mock.patch.object(self.lbm, 'ensure_vlan'),
            mock.patch.object(self.lbm, 'ensure_bridge'),
            mock.patch.object(self.lbm, 'get_interface_details'),
        ) as (ens_vl_fn, ens, get_int_det_fn):
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
        with mock.patch.object(self.lbm, 'device_exists') as de_fn:
            de_fn.return_value = True
            self.assertEqual(self.lbm.ensure_vlan("eth0", "1"), "eth0.1")
            de_fn.return_value = False
            with mock.patch.object(utils, 'execute') as exec_fn:
                exec_fn.return_value = False
                self.assertEqual(self.lbm.ensure_vlan("eth0", "1"), "eth0.1")
                exec_fn.assert_called_twice()
                exec_fn.return_value = True
                self.assertIsNone(self.lbm.ensure_vlan("eth0", "1"))
                exec_fn.assert_called_once()

    def test_ensure_vxlan(self):
        seg_id = "12345678"
        self.lbm.local_int = 'eth0'
        self.lbm.vxlan_mode = lconst.VXLAN_MCAST
        with mock.patch.object(self.lbm, 'device_exists') as de_fn:
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
        with contextlib.nested(
            mock.patch.object(ip_lib.IpAddrCommand, 'add'),
            mock.patch.object(ip_lib.IpAddrCommand, 'delete')
        ) as (add_fn, del_fn):
            self.lbm.update_interface_ip_details("br0", "eth0",
                                                 [ipdict], None)
            self.assertTrue(add_fn.called)
            self.assertTrue(del_fn.called)

        with contextlib.nested(
            mock.patch.object(ip_lib.IpRouteCommand, 'add_gateway'),
            mock.patch.object(ip_lib.IpRouteCommand, 'delete_gateway')
        ) as (addgw_fn, delgw_fn):
            self.lbm.update_interface_ip_details("br0", "eth0",
                                                 None, gwdict)
            self.assertTrue(addgw_fn.called)
            self.assertTrue(delgw_fn.called)

    def test_ensure_bridge(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, 'device_exists'),
            mock.patch.object(utils, 'execute'),
            mock.patch.object(self.lbm, 'update_interface_ip_details'),
            mock.patch.object(self.lbm, 'interface_exists_on_bridge'),
            mock.patch.object(self.lbm, 'is_device_on_bridge'),
            mock.patch.object(self.lbm, 'get_bridge_for_tap_device'),
        ) as (de_fn, exec_fn, upd_fn, ie_fn, if_br_fn, get_if_br_fn):
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
                          root_helper=self.root_helper),
                mock.call(['brctl', 'addif', 'br0', 'eth0'],
                          root_helper=self.root_helper),
            ]
            exec_fn.assert_has_calls(expected)

    def test_ensure_physical_in_bridge(self):
        self.assertFalse(
            self.lbm.ensure_physical_in_bridge("123", lconst.TYPE_VLAN,
                                               "phys", "1")
        )
        with mock.patch.object(self.lbm, "ensure_flat_bridge") as flbr_fn:
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", lconst.TYPE_FLAT,
                                                   "physnet1", None)
            )
            self.assertTrue(flbr_fn.called)
        with mock.patch.object(self.lbm, "ensure_vlan_bridge") as vlbr_fn:
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", lconst.TYPE_VLAN,
                                                   "physnet1", "1")
            )
            self.assertTrue(vlbr_fn.called)

        with mock.patch.object(self.lbm, "ensure_vxlan_bridge") as vlbr_fn:
            self.lbm.vxlan_mode = lconst.VXLAN_MCAST
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", lconst.TYPE_VXLAN,
                                                   "physnet1", "1")
            )
            self.assertTrue(vlbr_fn.called)

    def test_add_tap_interface(self):
        with mock.patch.object(self.lbm, "device_exists") as de_fn:
            de_fn.return_value = False
            self.assertFalse(
                self.lbm.add_tap_interface("123", lconst.TYPE_VLAN,
                                           "physnet1", "1", "tap1")
            )

            de_fn.return_value = True
            with contextlib.nested(
                mock.patch.object(self.lbm, "ensure_local_bridge"),
                mock.patch.object(utils, "execute"),
                mock.patch.object(self.lbm, "get_bridge_for_tap_device")
            ) as (en_fn, exec_fn, get_br):
                exec_fn.return_value = False
                get_br.return_value = True
                self.assertTrue(self.lbm.add_tap_interface("123",
                                                           lconst.TYPE_LOCAL,
                                                           "physnet1", None,
                                                           "tap1"))
                en_fn.assert_called_with("123")

                get_br.return_value = False
                exec_fn.return_value = True
                self.assertFalse(self.lbm.add_tap_interface("123",
                                                            lconst.TYPE_LOCAL,
                                                            "physnet1", None,
                                                            "tap1"))

            with mock.patch.object(self.lbm,
                                   "ensure_physical_in_bridge") as ens_fn:
                ens_fn.return_value = False
                self.assertFalse(self.lbm.add_tap_interface("123",
                                                            lconst.TYPE_VLAN,
                                                            "physnet1", "1",
                                                            "tap1"))

    def test_add_interface(self):
        with mock.patch.object(self.lbm, "add_tap_interface") as add_tap:
            self.lbm.add_interface("123", lconst.TYPE_VLAN, "physnet-1",
                                   "1", "234")
            add_tap.assert_called_with("123", lconst.TYPE_VLAN, "physnet-1",
                                       "1", "tap234")

    def test_delete_vlan_bridge(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, "device_exists"),
            mock.patch.object(self.lbm, "get_interfaces_on_bridge"),
            mock.patch.object(self.lbm, "remove_interface"),
            mock.patch.object(self.lbm, "get_interface_details"),
            mock.patch.object(self.lbm, "update_interface_ip_details"),
            mock.patch.object(self.lbm, "delete_vlan"),
            mock.patch.object(self.lbm, "delete_vxlan"),
            mock.patch.object(utils, "execute")
        ) as (de_fn, getif_fn, remif_fn, if_det_fn,
              updif_fn, del_vlan, del_vxlan, exec_fn):
            de_fn.return_value = False
            self.lbm.delete_vlan_bridge("br0")
            self.assertFalse(getif_fn.called)

            de_fn.return_value = True
            getif_fn.return_value = ["eth0", "eth1.1", "eth1", "vxlan-1002"]
            if_det_fn.return_value = ("ips", "gateway")
            exec_fn.return_value = False
            self.lbm.delete_vlan_bridge("br0")
            updif_fn.assert_called_with("eth1", "br0", "ips", "gateway")
            del_vlan.assert_called_with("eth1.1")
            del_vxlan.assert_called_with("vxlan-1002")

    def test_delete_vxlan_bridge_no_int_mappings(self):
        interface_mappings = {}
        lbm = linuxbridge_neutron_agent.LinuxBridgeManager(
            interface_mappings, self.root_helper)

        with contextlib.nested(
            mock.patch.object(lbm, "device_exists"),
            mock.patch.object(lbm, "get_interfaces_on_bridge"),
            mock.patch.object(lbm, "remove_interface"),
            mock.patch.object(lbm, "delete_vxlan"),
            mock.patch.object(utils, "execute")
        ) as (de_fn, getif_fn, remif_fn, del_vxlan, exec_fn):
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

        with contextlib.nested(
            mock.patch.object(self.lbm, "delete_vlan_bridge"),
            mock.patch.object(self.lbm, "get_tap_devices_count",
                              side_effect=tap_count_side_effect),
        ) as (del_br_fn, count_tap_fn):
            self.lbm.remove_empty_bridges()
            del_br_fn.assert_called_once_with('brqnet1')

    def test_remove_interface(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, "device_exists"),
            mock.patch.object(self.lbm, "is_device_on_bridge"),
            mock.patch.object(utils, "execute")
        ) as (de_fn, isdev_fn, exec_fn):
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
        with contextlib.nested(
            mock.patch.object(self.lbm, "device_exists"),
            mock.patch.object(utils, "execute")
        ) as (de_fn, exec_fn):
            de_fn.return_value = False
            self.lbm.delete_vlan("eth1.1")
            self.assertFalse(exec_fn.called)

            de_fn.return_value = True
            exec_fn.return_value = False
            self.lbm.delete_vlan("eth1.1")
            self.assertTrue(exec_fn.called)

    def test_update_devices(self):
        with mock.patch.object(self.lbm, "udev_get_tap_devices") as gt_fn:
            gt_fn.return_value = set(["dev1"])
            self.assertIsNone(self.lbm.update_devices(set(["dev1"])))

            gt_fn.return_value = set(["dev1", "dev2"])
            self.assertEqual(self.lbm.update_devices(set(["dev2", "dev3"])),
                             {"current": set(["dev1", "dev2"]),
                              "added": set(["dev1"]),
                              "removed": set(["dev3"])
                              })

    def _check_vxlan_support(self, kernel_version, vxlan_proxy_supported,
                             fdb_append_supported, l2_population,
                             expected_mode):
        def iproute_supported_side_effect(*args):
            if args[1] == 'proxy':
                return vxlan_proxy_supported
            elif args[1] == 'append':
                return fdb_append_supported

        with contextlib.nested(
            mock.patch("platform.release", return_value=kernel_version),
            mock.patch.object(ip_lib, 'iproute_arg_supported',
                              side_effect=iproute_supported_side_effect),
        ) as (kver_fn, ip_arg_fn):
            self.lbm.check_vxlan_support()
            self.assertEqual(self.lbm.vxlan_mode, expected_mode)

    def test_vxlan_mode_ucast(self):
        self._check_vxlan_support(kernel_version='3.12',
                                  vxlan_proxy_supported=True,
                                  fdb_append_supported=True,
                                  l2_population=True,
                                  expected_mode=lconst.VXLAN_MCAST)

    def test_vxlan_mode_mcast(self):
        self._check_vxlan_support(kernel_version='3.12',
                                  vxlan_proxy_supported=True,
                                  fdb_append_supported=False,
                                  l2_population=True,
                                  expected_mode=lconst.VXLAN_MCAST)
        self._check_vxlan_support(kernel_version='3.10',
                                  vxlan_proxy_supported=True,
                                  fdb_append_supported=True,
                                  l2_population=True,
                                  expected_mode=lconst.VXLAN_MCAST)

    def test_vxlan_mode_unsupported(self):
        self._check_vxlan_support(kernel_version='3.7',
                                  vxlan_proxy_supported=True,
                                  fdb_append_supported=True,
                                  l2_population=False,
                                  expected_mode=lconst.VXLAN_NONE)
        self._check_vxlan_support(kernel_version='3.10',
                                  vxlan_proxy_supported=False,
                                  fdb_append_supported=False,
                                  l2_population=False,
                                  expected_mode=lconst.VXLAN_NONE)
        cfg.CONF.set_override('vxlan_group', '', 'VXLAN')
        self._check_vxlan_support(kernel_version='3.12',
                                  vxlan_proxy_supported=True,
                                  fdb_append_supported=True,
                                  l2_population=True,
                                  expected_mode=lconst.VXLAN_NONE)


class TestLinuxBridgeRpcCallbacks(base.BaseTestCase):
    def setUp(self):
        cfg.CONF.set_override('local_ip', LOCAL_IP, 'VXLAN')
        self.addCleanup(cfg.CONF.reset)
        super(TestLinuxBridgeRpcCallbacks, self).setUp()

        self.u_execute_p = mock.patch('neutron.agent.linux.utils.execute')
        self.u_execute = self.u_execute_p.start()
        self.addCleanup(self.u_execute_p.stop)

        class FakeLBAgent(object):
            def __init__(self):
                self.agent_id = 1
                self.br_mgr = (linuxbridge_neutron_agent.
                               LinuxBridgeManager({'physnet1': 'eth1'},
                                                  cfg.CONF.AGENT.root_helper))

                self.br_mgr.vxlan_mode = lconst.VXLAN_UCAST
                segment = mock.Mock()
                segment.network_type = 'vxlan'
                segment.segmentation_id = 1
                self.br_mgr.network_map['net_id'] = segment

        self.lb_rpc = linuxbridge_neutron_agent.LinuxBridgeRpcCallbacks(
            object(),
            FakeLBAgent()
        )

        self.root_helper = cfg.CONF.AGENT.root_helper

    def test_network_delete(self):
        with contextlib.nested(
            mock.patch.object(self.lb_rpc.agent.br_mgr, "get_bridge_name"),
            mock.patch.object(self.lb_rpc.agent.br_mgr, "delete_vlan_bridge")
        ) as (get_br_fn, del_fn):
            get_br_fn.return_value = "br0"
            self.lb_rpc.network_delete("anycontext", network_id="123")
            get_br_fn.assert_called_with("123")
            del_fn.assert_called_with("br0")

    def test_port_update(self):
        with contextlib.nested(
            mock.patch.object(self.lb_rpc.agent.br_mgr,
                              "get_tap_device_name"),
            mock.patch.object(self.lb_rpc.agent.br_mgr,
                              "udev_get_tap_devices"),
            mock.patch.object(self.lb_rpc.agent.br_mgr,
                              "get_bridge_name"),
            mock.patch.object(self.lb_rpc.agent.br_mgr,
                              "remove_interface"),
            mock.patch.object(self.lb_rpc.agent.br_mgr, "add_interface"),
            mock.patch.object(self.lb_rpc.agent,
                              "plugin_rpc", create=True),
            mock.patch.object(self.lb_rpc.sg_agent,
                              "refresh_firewall", create=True)
        ) as (get_tap_fn, udev_fn, getbr_fn, remif_fn,
              addif_fn, rpc_obj, reffw_fn):
            get_tap_fn.return_value = "tap123"
            udev_fn.return_value = ["tap123", "tap124"]
            port = {"admin_state_up": True,
                    "id": "1234-5678",
                    "network_id": "123-123"}
            self.lb_rpc.port_update("unused_context", port=port,
                                    vlan_id="1", physical_network="physnet1")
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_VLAN,
                                        "physnet1", "1", port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    network_type=lconst.TYPE_VLAN,
                                    segmentation_id="2",
                                    physical_network="physnet1")
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_VLAN,
                                        "physnet1", "2", port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    vlan_id=lconst.FLAT_VLAN_ID,
                                    physical_network="physnet1")
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_FLAT,
                                        "physnet1", None, port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    network_type=lconst.TYPE_FLAT,
                                    segmentation_id=None,
                                    physical_network="physnet1")
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_FLAT,
                                        "physnet1", None, port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    vlan_id=lconst.LOCAL_VLAN_ID,
                                    physical_network=None)
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_LOCAL,
                                        None, None, port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    network_type=lconst.TYPE_LOCAL,
                                    segmentation_id=None,
                                    physical_network=None)
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_LOCAL,
                                        None, None, port["id"])

            port["admin_state_up"] = False
            port["security_groups"] = True
            getbr_fn.return_value = "br0"
            self.lb_rpc.port_update("unused_context", port=port,
                                    vlan_id="1", physical_network="physnet1")
            self.assertTrue(reffw_fn.called)
            remif_fn.assert_called_with("br0", "tap123")
            rpc_obj.update_device_down.assert_called_with(
                self.lb_rpc.context,
                "tap123",
                self.lb_rpc.agent.agent_id,
                cfg.CONF.host
            )

    def test_port_update_plugin_rpc_failed(self):
        with contextlib.nested(
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "get_tap_device_name"),
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "udev_get_tap_devices"),
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "get_bridge_name"),
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "remove_interface"),
                mock.patch.object(self.lb_rpc.agent.br_mgr, "add_interface"),
                mock.patch.object(self.lb_rpc.sg_agent,
                                  "refresh_firewall", create=True),
                mock.patch.object(self.lb_rpc.agent,
                                  "plugin_rpc", create=True),
                mock.patch.object(linuxbridge_neutron_agent.LOG, 'error'),
        ) as (get_tap_fn, udev_fn, _, _, _, _, plugin_rpc, log):
            get_tap_fn.return_value = "tap123"
            udev_fn.return_value = ["tap123", "tap124"]
            port = {"admin_state_up": True,
                    "id": "1234-5678",
                    "network_id": "123-123"}
            plugin_rpc.update_device_up.side_effect = rpc_common.Timeout
            self.lb_rpc.port_update(mock.Mock(), port=port)
            self.assertTrue(plugin_rpc.update_device_up.called)
            self.assertEqual(log.call_count, 1)

            log.reset_mock()
            port["admin_state_up"] = False
            plugin_rpc.update_device_down.side_effect = rpc_common.Timeout
            self.lb_rpc.port_update(mock.Mock(), port=port)
            self.assertTrue(plugin_rpc.update_device_down.called)
            self.assertEqual(log.call_count, 1)

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
                          root_helper=self.root_helper),
                mock.call(['bridge', 'fdb', 'add',
                           constants.FLOODING_ENTRY[0],
                           'dev', 'vxlan-1', 'dst', 'agent_ip'],
                          root_helper=self.root_helper,
                          check_exit_code=False),
                mock.call(['ip', 'neigh', 'add', 'port_ip', 'lladdr',
                           'port_mac', 'dev', 'vxlan-1', 'nud', 'permanent'],
                          root_helper=self.root_helper,
                          check_exit_code=False),
                mock.call(['bridge', 'fdb', 'add', 'port_mac', 'dev',
                           'vxlan-1', 'dst', 'agent_ip'],
                          root_helper=self.root_helper,
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
                          root_helper=self.root_helper,
                          check_exit_code=False),
                mock.call(['ip', 'neigh', 'del', 'port_ip', 'lladdr',
                           'port_mac', 'dev', 'vxlan-1'],
                          root_helper=self.root_helper,
                          check_exit_code=False),
                mock.call(['bridge', 'fdb', 'del', 'port_mac',
                           'dev', 'vxlan-1', 'dst', 'agent_ip'],
                          root_helper=self.root_helper,
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
                mock.call(['ip', 'neigh', 'add', 'port_ip_2', 'lladdr',
                           'port_mac', 'dev', 'vxlan-1', 'nud', 'permanent'],
                          root_helper=self.root_helper,
                          check_exit_code=False),
                mock.call(['ip', 'neigh', 'del', 'port_ip_1', 'lladdr',
                           'port_mac', 'dev', 'vxlan-1'],
                          root_helper=self.root_helper,
                          check_exit_code=False)
            ]
            execute_fn.assert_has_calls(expected)
