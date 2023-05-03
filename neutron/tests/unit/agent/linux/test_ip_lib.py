# Copyright 2012 OpenStack Foundation
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

import copy
import errno
import socket
from unittest import mock

import netaddr
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_utils import netutils
from oslo_utils import uuidutils
from pyroute2.netlink import exceptions as netlink_exceptions
from pyroute2.netlink.rtnl import ifinfmsg
from pyroute2.netlink.rtnl import ndmsg
from pyroute2 import netns
from pyroute2.nslink import nslink
import testtools

from neutron.agent.common import utils  # noqa
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron import privileged
from neutron.privileged.agent.linux import ip_lib as priv_lib
from neutron.tests import base

NETNS_SAMPLE = [
    '12345678-1234-5678-abcd-1234567890ab',
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'cccccccc-cccc-cccc-cccc-cccccccccccc']

GATEWAY_SAMPLE1 = ("""
default via 10.35.19.254  metric 100
10.35.16.0/22  proto kernel  scope link  src 10.35.17.97
""")

GATEWAY_SAMPLE2 = ("""
default via 10.35.19.254  metric 100
""")

GATEWAY_SAMPLE3 = ("""
10.35.16.0/22  proto kernel  scope link  src 10.35.17.97
""")

GATEWAY_SAMPLE4 = ("""
default via 10.35.19.254
""")

GATEWAY_SAMPLE5 = ("""
default via 192.168.99.1 proto static
""")

GATEWAY_SAMPLE6 = ("""
default via 192.168.99.1 proto static metric 100
""")

GATEWAY_SAMPLE7 = ("""
default dev qg-31cd36 metric 1
""")

IPv6_GATEWAY_SAMPLE1 = ("""
default via 2001:470:9:1224:4508:b885:5fb:740b metric 100
2001:db8::/64 proto kernel scope link src 2001:470:9:1224:dfcc:aaff:feb9:76ce
""")

IPv6_GATEWAY_SAMPLE2 = ("""
default via 2001:470:9:1224:4508:b885:5fb:740b metric 100
""")

IPv6_GATEWAY_SAMPLE3 = ("""
2001:db8::/64 proto kernel scope link src 2001:470:9:1224:dfcc:aaff:feb9:76ce
""")

IPv6_GATEWAY_SAMPLE4 = ("""
default via fe80::dfcc:aaff:feb9:76ce
""")

IPv6_GATEWAY_SAMPLE5 = ("""
default via 2001:470:9:1224:4508:b885:5fb:740b metric 1024
""")

DEVICE_ROUTE_SAMPLE = ("10.0.0.0/24  scope link  src 10.0.0.2")

SUBNET_SAMPLE1 = ("10.0.0.0/24 dev qr-23380d11-d2  scope link  src 10.0.0.1\n"
                  "10.0.0.0/24 dev tap1d7888a7-10  scope link  src 10.0.0.2")
SUBNET_SAMPLE2 = ("10.0.0.0/24 dev tap1d7888a7-10  scope link  src 10.0.0.2\n"
                  "10.0.0.0/24 dev qr-23380d11-d2  scope link  src 10.0.0.1")

VXLAN4_GROUP_SAMPLE = "239.0.0.1"

VXLAN4_LOCAL_SAMPLE = "192.168.45.100"

VXLAN6_GROUP_SAMPLE = "ff00::1"

VXLAN6_INVALID_IPV6_SAMPLE = "invalid:ipv6::address"

VXLAN6_LOCAL_SAMPLE = "fd00::1"


class TestSubProcessBase(base.BaseTestCase):
    def setUp(self):
        super(TestSubProcessBase, self).setUp()
        self.execute_p = mock.patch('neutron.agent.common.utils.execute')
        self.execute = self.execute_p.start()

    def test_execute_wrapper(self):
        base = ip_lib.SubProcessBase()
        base._execute(['o'], 'link', ('list',), run_as_root=True)

        self.execute.assert_called_once_with(['ip', '-o', 'link', 'list'],
                                             run_as_root=True,
                                             privsep_exec=True,
                                             log_fail_as_error=True)

    def test_execute_wrapper_int_options(self):
        base = ip_lib.SubProcessBase()
        base._execute([4], 'link', ('list',))

        self.execute.assert_called_once_with(['ip', '-4', 'link', 'list'],
                                             run_as_root=False,
                                             privsep_exec=True,
                                             log_fail_as_error=True)

    def test_execute_wrapper_no_options(self):
        base = ip_lib.SubProcessBase()
        base._execute([], 'link', ('list',))

        self.execute.assert_called_once_with(['ip', 'link', 'list'],
                                             run_as_root=False,
                                             privsep_exec=True,
                                             log_fail_as_error=True)

    def test_run_no_namespace(self):
        base = ip_lib.SubProcessBase()
        base._run([], 'link', ('list',))
        self.execute.assert_called_once_with(['ip', 'link', 'list'],
                                             run_as_root=False,
                                             privsep_exec=True,
                                             log_fail_as_error=True)

    def test_run_namespace(self):
        base = ip_lib.SubProcessBase(namespace='ns')
        base._run([], 'link', ('list',))
        self.execute.assert_called_once_with(['ip', 'netns', 'exec', 'ns',
                                              'ip', 'link', 'list'],
                                             run_as_root=True,
                                             privsep_exec=True,
                                             log_fail_as_error=True)

    def test_as_root_namespace(self):
        base = ip_lib.SubProcessBase(namespace='ns')
        base._as_root([], 'link', ('list',))
        self.execute.assert_called_once_with(['ip', 'netns', 'exec', 'ns',
                                              'ip', 'link', 'list'],
                                             run_as_root=True,
                                             privsep_exec=True,
                                             log_fail_as_error=True)


class TestIpWrapper(base.BaseTestCase):
    def setUp(self):
        super(TestIpWrapper, self).setUp()
        self.execute_p = mock.patch.object(ip_lib.IPWrapper, '_execute')
        self.execute = self.execute_p.start()

    @mock.patch.object(priv_lib, 'get_device_names')
    def test_get_devices(self, mock_get_devices):
        interfaces = ['br01', 'lo', 'gre0']
        mock_get_devices.return_value = interfaces
        devices = ip_lib.IPWrapper(namespace='foo').get_devices()
        for device in devices:
            self.assertEqual('br01', device.name)
            interfaces.remove(device.name)

    @mock.patch.object(priv_lib, 'get_device_names')
    def test_get_devices_include_loopback_and_gre(self, mock_get_devices):
        interfaces = ['br01', 'lo', 'gre0']
        mock_get_devices.return_value = interfaces
        devices = ip_lib.IPWrapper(namespace='foo').get_devices(
            exclude_loopback=False, exclude_fb_tun_devices=False)
        for device in devices:
            self.assertIn(device.name, interfaces)
            interfaces.remove(device.name)
        self.assertEqual(0, len(interfaces))

    @mock.patch.object(priv_lib, 'get_device_names')
    def test_get_devices_no_netspace(self, mock_get_devices):
        mock_get_devices.side_effect = priv_lib.NetworkNamespaceNotFound(
            netns_name='foo')
        self.assertEqual([], ip_lib.IPWrapper(namespace='foo').get_devices())

    @mock.patch.object(netns, 'listnetns')
    @mock.patch.object(priv_lib, 'list_netns')
    def test_get_namespaces_non_root(self, priv_listnetns, listnetns):
        self.config(group='AGENT', use_helper_for_ns_read=False)
        listnetns.return_value = NETNS_SAMPLE
        retval = ip_lib.list_network_namespaces()
        self.assertEqual(retval,
                         ['12345678-1234-5678-abcd-1234567890ab',
                          'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
                          'cccccccc-cccc-cccc-cccc-cccccccccccc'])
        self.assertEqual(1, listnetns.call_count)
        self.assertFalse(priv_listnetns.called)

    @mock.patch.object(netns, 'listnetns')
    @mock.patch.object(priv_lib, 'list_netns')
    def test_get_namespaces_root(self, priv_listnetns, listnetns):
        self.config(group='AGENT', use_helper_for_ns_read=True)
        priv_listnetns.return_value = NETNS_SAMPLE
        retval = ip_lib.list_network_namespaces()
        self.assertEqual(retval,
                         ['12345678-1234-5678-abcd-1234567890ab',
                          'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
                          'cccccccc-cccc-cccc-cccc-cccccccccccc'])
        self.assertEqual(1, priv_listnetns.call_count)
        self.assertFalse(listnetns.called)

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_tuntap(self, create):
        ip_lib.IPWrapper().add_tuntap('tap0')
        create.assert_called_once_with('tap0', None, 'tuntap', mode='tap')

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_veth(self, create):
        ip_lib.IPWrapper().add_veth('tap0', 'tap1')
        create.assert_called_once_with(
            'tap0', None, 'veth', peer={'ifname': 'tap1'})

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_macvtap(self, create):
        ip_lib.IPWrapper().add_macvtap('macvtap0', 'eth0', 'bridge')
        create.assert_called_once_with(
            'macvtap0', None, 'macvtap', physical_interface='eth0',
            mode='bridge')

    @mock.patch.object(priv_lib, 'delete_interface')
    def test_del_veth(self, delete):
        ip_lib.IPWrapper().del_veth('fpr-1234')
        delete.assert_called_once_with('fpr-1234', None)

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_veth_with_namespaces(self, create):
        ns2 = 'ns2'
        with mock.patch.object(ip_lib.IPWrapper, 'ensure_namespace') as en:
            ip_lib.IPWrapper().add_veth('tap0', 'tap1', namespace2=ns2)
            en.assert_has_calls([mock.call(ns2)])
        create.assert_called_once_with(
            'tap0', None, 'veth',
            peer={'ifname': 'tap1', 'net_ns_fd': 'ns2'})

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_dummy(self, create):
        ip_lib.IPWrapper().add_dummy('dummy0')
        create.assert_called_once_with('dummy0', None, 'dummy')

    def test_get_device(self):
        dev = ip_lib.IPWrapper(namespace='ns').device('eth0')
        self.assertEqual(dev.namespace, 'ns')
        self.assertEqual(dev.name, 'eth0')

    @mock.patch.object(priv_lib, 'create_netns')
    def test_ensure_namespace(self, create):
        with mock.patch.object(ip_lib, 'IPDevice') as ip_dev:
            ip = ip_lib.IPWrapper()
            with mock.patch.object(ip.netns, 'exists') as ns_exists:
                with mock.patch('neutron.agent.common.utils.execute'):
                    ns_exists.return_value = False
                    ip.ensure_namespace('ns')
                    create.assert_called_once_with('ns')
                    ns_exists.assert_called_once_with('ns')
                    ip_dev.assert_has_calls([mock.call('lo', namespace='ns'),
                                             mock.call().link.set_up()])

    def test_ensure_namespace_existing(self):
        with mock.patch.object(ip_lib, 'IpNetnsCommand') as ip_ns_cmd:
            ip_ns_cmd.exists.return_value = True
            ns = ip_lib.IPWrapper().ensure_namespace('ns')
            self.assertFalse(self.execute.called)
            self.assertEqual(ns.namespace, 'ns')

    def test_namespace_is_empty_no_devices(self):
        ip = ip_lib.IPWrapper(namespace='ns')
        with mock.patch.object(ip, 'get_devices') as get_devices:
            get_devices.return_value = []

            self.assertTrue(ip.namespace_is_empty())
            self.assertTrue(get_devices.called)

    def test_namespace_is_empty(self):
        ip = ip_lib.IPWrapper(namespace='ns')
        with mock.patch.object(ip, 'get_devices') as get_devices:
            get_devices.return_value = [mock.Mock()]

            self.assertFalse(ip.namespace_is_empty())
            self.assertTrue(get_devices.called)

    def test_garbage_collect_namespace_does_not_exist(self):
        with mock.patch.object(ip_lib, 'IpNetnsCommand') as ip_ns_cmd_cls:
            ip_ns_cmd_cls.return_value.exists.return_value = False
            ip = ip_lib.IPWrapper(namespace='ns')
            with mock.patch.object(ip, 'namespace_is_empty') as mock_is_empty:

                self.assertFalse(ip.garbage_collect_namespace())
                ip_ns_cmd_cls.assert_has_calls([mock.call().exists('ns')])
                self.assertNotIn(mock.call().delete('ns'),
                                 ip_ns_cmd_cls.return_value.mock_calls)
                self.assertEqual([], mock_is_empty.mock_calls)

    def test_garbage_collect_namespace_existing_empty_ns(self):
        with mock.patch.object(ip_lib, 'IpNetnsCommand') as ip_ns_cmd_cls:
            ip_ns_cmd_cls.return_value.exists.return_value = True

            ip = ip_lib.IPWrapper(namespace='ns')

            with mock.patch.object(ip, 'namespace_is_empty') as mock_is_empty:
                mock_is_empty.return_value = True
                self.assertTrue(ip.garbage_collect_namespace())

                mock_is_empty.assert_called_once_with()
                expected = [mock.call().exists('ns'),
                            mock.call().delete('ns')]
                ip_ns_cmd_cls.assert_has_calls(expected)

    def test_garbage_collect_namespace_existing_not_empty(self):
        lo_device = mock.Mock()
        lo_device.name = 'lo'
        tap_device = mock.Mock()
        tap_device.name = 'tap1'

        with mock.patch.object(ip_lib, 'IpNetnsCommand') as ip_ns_cmd_cls:
            ip_ns_cmd_cls.return_value.exists.return_value = True

            ip = ip_lib.IPWrapper(namespace='ns')

            with mock.patch.object(ip, 'namespace_is_empty') as mock_is_empty:
                mock_is_empty.return_value = False

                self.assertFalse(ip.garbage_collect_namespace())

                mock_is_empty.assert_called_once_with()
                expected = [mock.call(ip),
                            mock.call().exists('ns')]
                self.assertEqual(ip_ns_cmd_cls.mock_calls, expected)
                self.assertNotIn(mock.call().delete('ns'),
                                 ip_ns_cmd_cls.mock_calls)

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_vlan(self, create):
        retval = ip_lib.IPWrapper().add_vlan('eth0.1', 'eth0', '1')
        self.assertIsInstance(retval, ip_lib.IPDevice)
        self.assertEqual(retval.name, 'eth0.1')
        create.assert_called_once_with('eth0.1',
                                       None,
                                       'vlan',
                                       physical_interface='eth0',
                                       vlan_id='1')

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_vxlan_valid_srcport_length(self, create):
        self.call_params = {}

        def fake_create_interface(ifname, namespace, kind, **kwargs):
            self.call_params = dict(
                ifname=ifname,
                namespace=namespace,
                kind=kind,
                **kwargs)

        create.side_effect = fake_create_interface
        expected_call_params = {
            'ifname': 'vxlan0',
            'namespace': None,
            'kind': 'vxlan',
            'vxlan_id': 'vni0',
            'vxlan_group': VXLAN4_GROUP_SAMPLE,
            'physical_interface': 'dev0',
            'vxlan_ttl': 'ttl0',
            'vxlan_tos': 'tos0',
            'vxlan_local': VXLAN4_LOCAL_SAMPLE,
            'vxlan_proxy': True,
            'vxlan_port_range': ('1', '2')}

        retval = ip_lib.IPWrapper().add_vxlan('vxlan0', 'vni0',
                                              group=VXLAN4_GROUP_SAMPLE,
                                              dev='dev0', ttl='ttl0',
                                              tos='tos0',
                                              local=VXLAN4_LOCAL_SAMPLE,
                                              proxy=True, srcport=(1, 2))
        self.assertIsInstance(retval, ip_lib.IPDevice)
        self.assertEqual(retval.name, 'vxlan0')
        self.assertDictEqual(expected_call_params, self.call_params)

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_vxlan6_valid_srcport_length(self, create):
        self.call_params = {}

        def fake_create_interface(ifname, namespace, kind, **kwargs):
            self.call_params = dict(
                ifname=ifname,
                namespace=namespace,
                kind=kind,
                **kwargs)

        create.side_effect = fake_create_interface
        expected_call_params = {
            'ifname': 'vxlan0',
            'namespace': None,
            'kind': 'vxlan',
            'vxlan_id': 'vni0',
            'vxlan_group6': VXLAN6_GROUP_SAMPLE,
            'physical_interface': 'dev0',
            'vxlan_ttl': 'ttl0',
            'vxlan_tos': 'tos0',
            'vxlan_local6': VXLAN6_LOCAL_SAMPLE,
            'vxlan_proxy': True,
            'vxlan_port_range': ('1', '2')}

        retval = ip_lib.IPWrapper().add_vxlan('vxlan0', 'vni0', 'dev0',
                                              group=VXLAN6_GROUP_SAMPLE,
                                              ttl='ttl0', tos='tos0',
                                              local=VXLAN6_LOCAL_SAMPLE,
                                              proxy=True, srcport=(1, 2))
        self.assertIsInstance(retval, ip_lib.IPDevice)
        self.assertEqual(retval.name, 'vxlan0')
        self.assertDictEqual(expected_call_params, self.call_params)

    def test_add_vxlan_invalid_srcport_length(self):
        wrapper = ip_lib.IPWrapper()
        self.assertRaises(exceptions.NetworkVxlanPortRangeError,
                          wrapper.add_vxlan, 'vxlan0', 'vni0',
                          group=VXLAN4_GROUP_SAMPLE, dev='dev0', ttl='ttl0',
                          tos='tos0', local=VXLAN4_LOCAL_SAMPLE, proxy=True,
                          srcport=('1', '2', '3'))

    def test_add_vxlan_invalid_srcport_range(self):
        wrapper = ip_lib.IPWrapper()
        self.assertRaises(exceptions.NetworkVxlanPortRangeError,
                          wrapper.add_vxlan, 'vxlan0', 'vni0',
                          group=VXLAN4_GROUP_SAMPLE, dev='dev0', ttl='ttl0',
                          tos='tos0', local=VXLAN4_LOCAL_SAMPLE, proxy=True,
                          srcport=(2000, 1000))

    def test_add_vxlan_invalid_ipv6_groupaddr(self):
        wrapper = ip_lib.IPWrapper()
        self.assertRaises(exceptions.InvalidInput,
                          wrapper.add_vxlan, 'vxlan0', 'vni0',
                          group=VXLAN6_INVALID_IPV6_SAMPLE,
                          dev='dev0', ttl='ttl0', tos='tos0')

    def test_add_vxlan_invalid_ipv6_localaddr(self):
        wrapper = ip_lib.IPWrapper()
        self.assertRaises(exceptions.InvalidInput,
                          wrapper.add_vxlan, 'vxlan0', 'vni0',
                          local=VXLAN6_INVALID_IPV6_SAMPLE, dev='dev0',
                          ttl='ttl0', tos='tos0')

    @mock.patch.object(priv_lib, 'create_interface')
    def test_add_vxlan_dstport(self, create):
        self.call_params = {}

        def fake_create_interface(ifname, namespace, kind, **kwargs):
            self.call_params = dict(
                ifname=ifname,
                namespace=namespace,
                kind=kind,
                **kwargs)

        create.side_effect = fake_create_interface
        expected_call_params = {
            'ifname': 'vxlan0',
            'namespace': None,
            'kind': 'vxlan',
            'vxlan_id': 'vni0',
            'vxlan_group': VXLAN4_GROUP_SAMPLE,
            'physical_interface': 'dev0',
            'vxlan_ttl': 'ttl0',
            'vxlan_tos': 'tos0',
            'vxlan_local': VXLAN4_LOCAL_SAMPLE,
            'vxlan_proxy': True,
            'vxlan_port_range': ('1', '2'),
            'vxlan_port': 4789}

        retval = ip_lib.IPWrapper().add_vxlan('vxlan0', 'vni0', 'dev0',
                                              group=VXLAN4_GROUP_SAMPLE,
                                              ttl='ttl0', tos='tos0',
                                              local=VXLAN4_LOCAL_SAMPLE,
                                              proxy=True, srcport=(1, 2),
                                              dstport=4789)

        self.assertIsInstance(retval, ip_lib.IPDevice)
        self.assertEqual(retval.name, 'vxlan0')
        self.assertDictEqual(expected_call_params, self.call_params)

    def test_add_device_to_namespace(self):
        dev = mock.Mock()
        ip_lib.IPWrapper(namespace='ns').add_device_to_namespace(dev)
        dev.assert_has_calls([mock.call.link.set_netns('ns')])

    def test_add_device_to_namespace_is_none(self):
        dev = mock.Mock()
        ip_lib.IPWrapper().add_device_to_namespace(dev)
        self.assertEqual([], dev.mock_calls)


class TestIPDevice(base.BaseTestCase):
    def test_eq_same_name(self):
        dev1 = ip_lib.IPDevice('tap0')
        dev2 = ip_lib.IPDevice('tap0')
        self.assertEqual(dev1, dev2)

    def test_eq_diff_name(self):
        dev1 = ip_lib.IPDevice('tap0')
        dev2 = ip_lib.IPDevice('tap1')
        self.assertNotEqual(dev1, dev2)

    def test_eq_same_namespace(self):
        dev1 = ip_lib.IPDevice('tap0', 'ns1')
        dev2 = ip_lib.IPDevice('tap0', 'ns1')
        self.assertEqual(dev1, dev2)

    def test_eq_diff_namespace(self):
        dev1 = ip_lib.IPDevice('tap0', namespace='ns1')
        dev2 = ip_lib.IPDevice('tap0', namespace='ns2')
        self.assertNotEqual(dev1, dev2)

    def test_eq_other_is_none(self):
        dev1 = ip_lib.IPDevice('tap0', namespace='ns1')
        self.assertIsNotNone(dev1)

    def test_str(self):
        self.assertEqual(str(ip_lib.IPDevice('tap0')), 'tap0')


class TestIPDeviceCommandBase(base.BaseTestCase):
    def setUp(self):
        super(TestIPDeviceCommandBase, self).setUp()
        self.ip_dev = mock.Mock()
        self.ip_dev.name = 'eth0'
        self.ip_dev._execute = mock.Mock(return_value='executed')
        self.ip_cmd = ip_lib.IpDeviceCommandBase(self.ip_dev)
        self.ip_cmd.COMMAND = 'foo'

    def test_name_property(self):
        self.assertEqual(self.ip_cmd.name, 'eth0')


class TestIPCmdBase(base.BaseTestCase):
    def setUp(self):
        super(TestIPCmdBase, self).setUp()
        self.parent = mock.Mock()
        self.parent.name = 'eth0'

    def _assert_call(self, options, args):
        self.parent._run.assert_has_calls([
            mock.call(options, self.command, args)])


class TestIpRuleCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpRuleCommand, self).setUp()
        self.parent._as_root.return_value = ''
        self.ns = uuidutils.generate_uuid()
        self.parent.namespace = self.ns
        self.command = 'rule'
        self._mock_priv_list_ip_rules = mock.patch.object(priv_lib,
                                                          'list_ip_rules')
        self.mock_priv_list_ip_rules = self._mock_priv_list_ip_rules.start()
        self.addCleanup(self._stop_mock)

    def _stop_mock(self):
        self._mock_priv_list_ip_rules.stop()

    def _test_add_rule(self, ip, iif, table, priority):
        ip_version = netaddr.IPNetwork(ip).version
        ip_family = common_utils.get_socket_address_family(ip_version)
        table_num = ip_lib.IP_RULE_TABLES.get(table) or int(table)
        cmd_args = {'table': table_num,
                    'priority': priority,
                    'family': ip_family}
        if iif:
            cmd_args['iifname'] = iif
        else:
            cmd_args['src'] = ip
            cmd_args['src_len'] = common_utils.get_network_length(ip_version)

        with mock.patch.object(priv_lib, 'add_ip_rule') as mock_add_ip_rule:
            ip_lib.add_ip_rule('namespace', ip, iif=iif, table=table,
                               priority=priority)
            mock_add_ip_rule.assert_called_once_with('namespace', **cmd_args)

    def _test_add_rule_exists(self, ip, table, priority, output):
        self.parent._as_root.return_value = output
        with mock.patch.object(ip_lib, '_exist_ip_rule', return_value=True) \
                as mock_exists:
            ip_lib.add_ip_rule(self.ns, ip, table=table, priority=priority)
            kwargs = {'from': ip, 'priority': str(priority),
                      'table': str(table), 'type': 'unicast'}
            mock_exists.assert_called_once_with(
                common_utils.get_ip_version(ip), **kwargs)

    def _test_delete_rule(self, ip, table, priority):
        with mock.patch.object(priv_lib, 'delete_ip_rule') as mock_delete:
            ip_lib.delete_ip_rule(self.ns, ip, table=table, priority=priority)
            args = ip_lib._make_pyroute2_args(ip, None, table, priority, None)
            mock_delete.assert_called_with(self.ns, **args)

    def test_add_rule_v4(self):
        self._test_add_rule('192.168.45.100', None, 2, 100)

    def test_add_rule_v4_iif(self):
        self._test_add_rule('192.168.45.100', 'iif_name', 2, 100)

    def test_add_rule_v6(self):
        self._test_add_rule('2001:db8::1', None, 3, 200)

    def test_add_rule_table_string(self):
        self._test_add_rule('2001:db8::1', None, 'default', 200)
        self._test_add_rule('2001:db8::1', None, 'main', 200)
        self._test_add_rule('2001:db8::1', None, 'local', 200)
        self._test_add_rule('2001:db8::1', None, '100', 200)

    def test_delete_rule_v4(self):
        self._test_delete_rule('192.168.45.100', 2, 100)

    def test_delete_rule_v6(self):
        self._test_delete_rule('2001:db8::1', 3, 200)


class TestIpLinkCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpLinkCommand, self).setUp()
        self.command = 'link'
        self.link_cmd = ip_lib.IpLinkCommand(self.parent)

    @mock.patch.object(priv_lib, 'set_link_attribute')
    def test_set_address(self, set_link_attribute):
        self.link_cmd.set_address('aa:bb:cc:dd:ee:ff')
        set_link_attribute.assert_called_once_with(
            self.parent.name, self.parent.namespace,
            address='aa:bb:cc:dd:ee:ff')

    @mock.patch.object(priv_lib, 'set_link_flags')
    def test_set_allmulticast_on(self, set_link_flags):
        self.link_cmd.set_allmulticast_on()
        set_link_flags.assert_called_once_with(
            self.parent.name, self.parent.namespace, ifinfmsg.IFF_ALLMULTI)

    @mock.patch.object(priv_lib, 'set_link_attribute')
    def test_set_mtu(self, set_link_attribute):
        self.link_cmd.set_mtu(1500)
        set_link_attribute.assert_called_once_with(
            self.parent.name, self.parent.namespace, mtu=1500)

    @mock.patch.object(priv_lib, 'set_link_attribute')
    def test_set_up(self, set_link_attribute):
        self.link_cmd.set_up()
        set_link_attribute.assert_called_once_with(
            self.parent.name, self.parent.namespace, state='up')

    @mock.patch.object(priv_lib, 'set_link_attribute')
    def test_set_down(self, set_link_attribute):
        self.link_cmd.set_down()
        set_link_attribute.assert_called_once_with(
            self.parent.name, self.parent.namespace, state='down')

    @mock.patch.object(priv_lib, 'interface_exists', return_value=True)
    @mock.patch.object(priv_lib, 'set_link_attribute')
    def test_set_netns(self, set_link_attribute, *args):
        original_namespace = self.parent.namespace
        self.link_cmd.set_netns('foo')
        set_link_attribute.assert_called_once_with(
            'eth0', original_namespace, net_ns_fd='foo')
        self.assertEqual(self.parent.namespace, 'foo')

    @mock.patch.object(priv_lib, 'set_link_attribute')
    def test_set_name(self, set_link_attribute):
        original_name = self.parent.name
        self.link_cmd.set_name('tap1')
        set_link_attribute.assert_called_once_with(
            original_name, self.parent.namespace, ifname='tap1')
        self.assertEqual(self.parent.name, 'tap1')

    @mock.patch.object(priv_lib, 'set_link_attribute')
    def test_set_alias(self, set_link_attribute):
        self.link_cmd.set_alias('openvswitch')
        set_link_attribute.assert_called_once_with(
            self.parent.name, self.parent.namespace, ifalias='openvswitch')

    @mock.patch.object(priv_lib, 'create_interface')
    def test_create(self, create):
        self.link_cmd.create()
        create.assert_called_once_with(self.parent.name, self.parent.namespace,
                                       self.parent.kind)

    @mock.patch.object(priv_lib, 'delete_interface')
    def test_delete(self, delete):
        self.link_cmd.delete()
        delete.assert_called_once_with(self.parent.name, self.parent.namespace)

    @mock.patch.object(priv_lib, 'get_link_attributes')
    def test_settings_property(self, get_link_attributes):
        self.link_cmd.attributes
        get_link_attributes.assert_called_once_with(
            self.parent.name, self.parent.namespace)


class TestIpAddrCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpAddrCommand, self).setUp()
        self.parent.name = 'tap0'
        self.command = 'addr'
        self.addr_cmd = ip_lib.IpAddrCommand(self.parent)

    @mock.patch.object(priv_lib, 'add_ip_address')
    def test_add_address(self, add):
        self.addr_cmd.add('192.168.45.100/24')
        add.assert_called_once_with(
            4,
            '192.168.45.100',
            24,
            self.parent.name,
            self.addr_cmd._parent.namespace,
            'global',
            '192.168.45.255')

    @mock.patch.object(priv_lib, 'add_ip_address')
    def test_add_address_scoped(self, add):
        self.addr_cmd.add('192.168.45.100/24', scope='link')
        add.assert_called_once_with(
            4,
            '192.168.45.100',
            24,
            self.parent.name,
            self.addr_cmd._parent.namespace,
            'link',
            '192.168.45.255')

    @mock.patch.object(priv_lib, 'add_ip_address')
    def test_add_address_no_broadcast(self, add):
        self.addr_cmd.add('192.168.45.100/24', add_broadcast=False)
        add.assert_called_once_with(
            4,
            '192.168.45.100',
            24,
            self.parent.name,
            self.addr_cmd._parent.namespace,
            'global',
            None)

    @mock.patch.object(priv_lib, 'delete_ip_address')
    def test_del_address(self, delete):
        self.addr_cmd.delete('192.168.45.100/24')
        delete.assert_called_once_with(
            4,
            '192.168.45.100',
            24,
            self.parent.name,
            self.addr_cmd._parent.namespace)

    @mock.patch.object(priv_lib, 'flush_ip_addresses')
    def test_flush(self, flush):
        self.addr_cmd.flush(6)
        flush.assert_called_once_with(
            6, self.parent.name, self.addr_cmd._parent.namespace)

    def test_wait_until_address_ready(self):
        self.addr_cmd.list = mock.Mock(
            return_value=[{'tentative': False, 'dadfailed': False}])
        # this address is not tentative or failed so it should return
        self.assertIsNone(self.addr_cmd.wait_until_address_ready(
            '2001:470:9:1224:fd91:272:581e:3a32'))

    def test_wait_until_address_ready_non_existent_address(self):
        self.addr_cmd.list = mock.Mock(return_value=[])
        with testtools.ExpectedException(ip_lib.AddressNotReady):
            self.addr_cmd.wait_until_address_ready('abcd::1234')

    def test_wait_until_address_dadfailed(self):
        self.addr_cmd.list = mock.Mock(
            return_value=[{'tentative': True, 'dadfailed': True}])
        with testtools.ExpectedException(ip_lib.DADFailed):
            self.addr_cmd.wait_until_address_ready('abcd::1234')

    @mock.patch.object(common_utils, 'wait_until_true')
    def test_wait_until_address_ready_success_one_timeout(self, mock_wuntil):
        tentative_address = 'fe80::3023:39ff:febc:22ae'
        self.addr_cmd.list = mock.Mock(return_value=[
            dict(scope='link', dadfailed=False, tentative=True, dynamic=False,
                 cidr=tentative_address + '/64'),
            dict(scope='link', dadfailed=False, tentative=False, dynamic=False,
                 cidr=tentative_address + '/64')])
        self.assertIsNone(self.addr_cmd.wait_until_address_ready(
            tentative_address, wait_time=3))
        self.assertEqual(1, mock_wuntil.call_count)

    def test_wait_until_address_ready_timeout(self):
        tentative_address = 'fe80::3023:39ff:febc:22ae'
        self.addr_cmd.list = mock.Mock(return_value=[
            dict(scope='link', dadfailed=False, tentative=True, dynamic=False,
                 cidr=tentative_address + '/64')])
        with testtools.ExpectedException(ip_lib.AddressNotReady):
            self.addr_cmd.wait_until_address_ready(tentative_address,
                                                   wait_time=1)

    @mock.patch.object(ip_lib, 'get_devices_with_ip')
    def test_list(self, mock_get_dev_ip):
        self.addr_cmd._parent.namespace = 'test_ns'
        self.addr_cmd.list()
        mock_get_dev_ip.assert_called_once_with('test_ns',
                                                name=self.addr_cmd.name)

    @mock.patch.object(ip_lib, 'get_devices_with_ip')
    def test_list_scope(self, mock_get_dev_ip):
        self.addr_cmd._parent.namespace = 'test_ns'
        self.addr_cmd.list(scope='link')
        mock_get_dev_ip.assert_called_once_with('test_ns',
                                                name=self.addr_cmd.name,
                                                scope='link')

    @mock.patch.object(ip_lib, 'get_devices_with_ip')
    def test_list_to(self, mock_get_dev_ip):
        self.addr_cmd._parent.namespace = 'test_ns'
        cidrs = [{'cidr': '1.2.3.4', 'mask': None},
                 {'cidr': '1.2.3.4/24', 'mask': 24},
                 {'cidr': '2001:db8::1', 'mask': None},
                 {'cidr': '2001:db8::1/64', 'mask': 64}]
        for cidr in cidrs:
            self.addr_cmd.list(to=cidr['cidr'])
            args = {'name': self.addr_cmd.name,
                    'address': common_utils.cidr_to_ip(cidr['cidr'])}
            if cidr['mask']:
                args['mask'] = cidr['mask']
            mock_get_dev_ip.assert_called_once_with('test_ns', **args)
            mock_get_dev_ip.reset_mock()

    @mock.patch.object(ip_lib, 'get_devices_with_ip')
    def test_list_ip_version(self, mock_get_dev_ip):
        self.addr_cmd._parent.namespace = 'test_ns'
        ip_versions = [
            {'ip_version': constants.IP_VERSION_4, 'family': socket.AF_INET},
            {'ip_version': constants.IP_VERSION_6, 'family': socket.AF_INET6}]
        for ip_version in ip_versions:
            self.addr_cmd.list(ip_version=ip_version['ip_version'])
            mock_get_dev_ip.assert_called_once_with(
                'test_ns', name=self.addr_cmd.name,
                family=ip_version['family'])
            mock_get_dev_ip.reset_mock()

    @mock.patch.object(ip_lib, 'get_devices_with_ip')
    def test_list_filters_dynamic_permanent(self, mock_get_dev_ip):
        self.addr_cmd._parent.namespace = 'test_ns'
        mock_get_dev_ip.return_value = [{'dynamic': True}]
        retval = self.addr_cmd.list(filters=['dynamic'])
        self.assertEqual(1, len(retval))
        retval = self.addr_cmd.list(filters=['permanent'])
        self.assertEqual(0, len(retval))

    @mock.patch.object(ip_lib, 'get_devices_with_ip')
    def test_list_filters_tentative_dadfailed(self, mock_get_dev_ip):
        self.addr_cmd._parent.namespace = 'test_ns'
        mock_get_dev_ip.return_value = [{'tentative': True,
                                         'dadfailed': False}]
        retval = self.addr_cmd.list(filters=['tentative'])
        self.assertEqual(1, len(retval))
        retval = self.addr_cmd.list(filters=['tentative', 'dadfailed'])
        self.assertEqual(0, len(retval))


class TestIpNetnsCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpNetnsCommand, self).setUp()
        self.command = 'netns'
        self.netns_cmd = ip_lib.IpNetnsCommand(self.parent)

    @mock.patch.object(priv_lib, 'create_netns')
    def test_add_namespace(self, create):
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            ns = self.netns_cmd.add('ns')
            create.assert_called_once_with('ns')
            self.assertEqual(ns.namespace, 'ns')
            execute.assert_called_once_with(
                ['ip', 'netns', 'exec', 'ns',
                 'sysctl', '-w', 'net.ipv4.conf.all.promote_secondaries=1'],
                run_as_root=True, check_exit_code=True, extra_ok_codes=None,
                log_fail_as_error=True, privsep_exec=True)

    @mock.patch.object(priv_lib, 'remove_netns')
    def test_delete_namespace(self, remove):
        self.netns_cmd.delete('ns')
        remove.assert_called_once_with('ns')

    def test_execute(self):
        self.parent.namespace = 'ns'
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            self.netns_cmd.execute(['ip', 'link', 'list'])
            execute.assert_called_once_with(['ip', 'netns', 'exec', 'ns', 'ip',
                                             'link', 'list'],
                                            run_as_root=True,
                                            check_exit_code=True,
                                            extra_ok_codes=None,
                                            log_fail_as_error=True,
                                            privsep_exec=False)

    def test_execute_env_var_prepend(self):
        self.parent.namespace = 'ns'
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            env = dict(FOO=1, BAR=2)
            self.netns_cmd.execute(['ip', 'link', 'list'], env)
            execute.assert_called_once_with(
                ['ip', 'netns', 'exec', 'ns', 'env'] +
                ['%s=%s' % (k, v) for k, v in env.items()] +
                ['ip', 'link', 'list'],
                run_as_root=True, check_exit_code=True, extra_ok_codes=None,
                log_fail_as_error=True, privsep_exec=False)

    def test_execute_nosudo_with_no_namespace(self):
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            self.parent.namespace = None
            self.netns_cmd.execute(['test'])
            execute.assert_called_once_with(['test'],
                                            check_exit_code=True,
                                            extra_ok_codes=None,
                                            run_as_root=False,
                                            log_fail_as_error=True,
                                            privsep_exec=False)


class TestDeviceExists(base.BaseTestCase):
    def test_ensure_device_is_ready(self):
        ip_lib_mock = mock.Mock()
        with mock.patch.object(ip_lib, 'IPDevice', return_value=ip_lib_mock):
            self.assertTrue(ip_lib.ensure_device_is_ready("eth0"))
            self.assertTrue(ip_lib_mock.link.set_up.called)
            ip_lib_mock.reset_mock()
            # device doesn't exists
            ip_lib_mock.link.set_up.side_effect = RuntimeError
            self.assertFalse(ip_lib.ensure_device_is_ready("eth0"))

    def test_ensure_device_is_ready_no_link_address(self):
        with mock.patch.object(
                priv_lib, 'get_link_attributes') as get_link_attributes, \
                mock.patch.object(priv_lib, 'set_link_attribute') as \
                set_link_attribute, \
                mock.patch.object(priv_lib, 'interface_exists',
                                  return_value=True):
            get_link_attributes.return_value = {}
            self.assertFalse(ip_lib.ensure_device_is_ready("lo"))
            get_link_attributes.assert_called_once_with("lo", None)
            set_link_attribute.assert_not_called()

    def test_ensure_device_is_ready_no_device(self):
        with mock.patch.object(priv_lib, 'interface_exists',
                               return_value=False):
            self.assertFalse(ip_lib.ensure_device_is_ready("lo"))


class TestIpNeighCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpNeighCommand, self).setUp()
        self.parent.name = 'tap0'
        self.command = 'neigh'
        self.neigh_cmd = ip_lib.IpNeighCommand(self.parent)
        self.addCleanup(privileged.default.set_client_mode, True)
        privileged.default.set_client_mode(False)

    @mock.patch.object(nslink, 'NetNS')
    def test_add_entry(self, mock_netns):
        mock_netns_instance = mock_netns.return_value
        mock_netns_enter = mock_netns_instance.__enter__.return_value
        mock_netns_enter.link_lookup.return_value = [1]
        self.neigh_cmd.add('192.168.45.100', 'cc:dd:ee:ff:ab:cd')
        mock_netns_enter.link_lookup.assert_called_once_with(ifname='tap0')
        mock_netns_enter.neigh.assert_called_once_with(
            'replace',
            dst='192.168.45.100',
            lladdr='cc:dd:ee:ff:ab:cd',
            family=2,
            ifindex=1,
            state=ndmsg.states['permanent'])

    @mock.patch.object(nslink, 'NetNS')
    def test_add_entry_nonexistent_namespace(self, mock_netns):
        mock_netns.side_effect = OSError(errno.ENOENT, None)
        with testtools.ExpectedException(ip_lib.NetworkNamespaceNotFound):
            self.neigh_cmd.add('192.168.45.100', 'cc:dd:ee:ff:ab:cd')

    @mock.patch.object(nslink, 'NetNS')
    def test_add_entry_other_error(self, mock_netns):
        expected_exception = OSError(errno.EACCES, None)
        mock_netns.side_effect = expected_exception
        with testtools.ExpectedException(expected_exception.__class__):
            self.neigh_cmd.add('192.168.45.100', 'cc:dd:ee:ff:ab:cd')

    @mock.patch.object(nslink, 'NetNS')
    def test_delete_entry(self, mock_netns):
        mock_netns_instance = mock_netns.return_value
        mock_netns_enter = mock_netns_instance.__enter__.return_value
        mock_netns_enter.link_lookup.return_value = [1]
        self.neigh_cmd.delete('192.168.45.100', 'cc:dd:ee:ff:ab:cd')
        mock_netns_enter.link_lookup.assert_called_once_with(ifname='tap0')
        mock_netns_enter.neigh.assert_called_once_with(
            'delete',
            dst='192.168.45.100',
            lladdr='cc:dd:ee:ff:ab:cd',
            family=2,
            ifindex=1)

    @mock.patch.object(priv_lib, '_run_iproute_neigh')
    def test_delete_entry_not_exist(self, mock_run_iproute):
        # trying to delete a non-existent entry shouldn't raise an error
        mock_run_iproute.side_effect = netlink_exceptions.NetlinkError(
            errno.ENOENT, None)
        self.neigh_cmd.delete('192.168.45.100', 'cc:dd:ee:ff:ab:cd')

    @mock.patch.object(nslink, 'NetNS')
    def test_dump_entries(self, mock_netns):
        mock_netns_instance = mock_netns.return_value
        mock_netns_enter = mock_netns_instance.__enter__.return_value
        mock_netns_enter.link_lookup.return_value = [1]
        self.neigh_cmd.dump(4)
        mock_netns_enter.link_lookup.assert_called_once_with(ifname='tap0')
        mock_netns_enter.neigh.assert_called_once_with(
            'dump',
            family=2,
            ifindex=1)

    def test_flush(self):
        with mock.patch.object(self.neigh_cmd, 'dump') as mock_dump, \
                mock.patch.object(self.neigh_cmd, 'delete') as mock_delete:
            mock_dump.return_value = (
                {'state': 'permanent', 'dst': '1.2.3.4', 'lladdr': 'mac_1'},
                {'state': 'reachable', 'dst': '1.2.3.5', 'lladdr': 'mac_2'})
            self.neigh_cmd.flush(4, '1.2.3.4')
            mock_delete.assert_not_called()
            self.neigh_cmd.flush(4, '1.2.3.5')
            mock_delete.assert_called_once_with('1.2.3.5', 'mac_2')


class TestArpPing(TestIPCmdBase):
    @mock.patch.object(ip_lib, 'IPWrapper')
    @mock.patch('eventlet.spawn_n')
    def test_send_ipv4_addr_adv_notif(self, spawn_n, mIPWrapper):
        spawn_n.side_effect = lambda f: f()
        ARPING_COUNT = 3
        address = '20.0.0.1'
        ip_lib.send_ip_addr_adv_notif(mock.sentinel.ns_name,
                                      mock.sentinel.iface_name,
                                      address,
                                      ARPING_COUNT)

        self.assertTrue(spawn_n.called)
        mIPWrapper.assert_has_calls([
            mock.call(namespace=mock.sentinel.ns_name),
            mock.call().netns.execute(mock.ANY, extra_ok_codes=[1],
                                      privsep_exec=True),
            mock.call().netns.execute(mock.ANY, extra_ok_codes=[1],
                                      privsep_exec=True),
            mock.call().netns.execute(mock.ANY, extra_ok_codes=[1, 2],
                                      privsep_exec=True),
            mock.call().netns.execute(mock.ANY, extra_ok_codes=[1, 2],
                                      privsep_exec=True),
            mock.call().netns.execute(mock.ANY, extra_ok_codes=[1, 2],
                                      privsep_exec=True),
            mock.call().netns.execute(mock.ANY, extra_ok_codes=[1, 2],
                                      privsep_exec=True)])

        ip_wrapper = mIPWrapper(namespace=mock.sentinel.ns_name)

        # Just test that arping is called with the right arguments
        for arg in ('-A', '-U'):
            arping_cmd = ['arping', arg,
                          '-I', mock.sentinel.iface_name,
                          '-c', 1,
                          '-w', mock.ANY,
                          address]
            ip_wrapper.netns.execute.assert_any_call(arping_cmd,
                                                     extra_ok_codes=mock.ANY,
                                                     privsep_exec=True)

    @mock.patch.object(ip_lib, 'IPWrapper')
    @mock.patch('eventlet.spawn_n')
    def test_send_ipv4_addr_adv_notif_nodev(self, spawn_n, mIPWrapper):
        spawn_n.side_effect = lambda f: f()
        ip_wrapper = mIPWrapper(namespace=mock.sentinel.ns_name)
        ip_wrapper.netns.execute.side_effect = RuntimeError
        ARPING_COUNT = 3
        address = '20.0.0.1'
        with mock.patch.object(ip_lib, 'device_exists_with_ips_and_mac',
                               return_value=False):
            ip_lib.send_ip_addr_adv_notif(mock.sentinel.ns_name,
                                          mock.sentinel.iface_name,
                                          address,
                                          ARPING_COUNT)

        # should return early with a single call when ENODEV
        mIPWrapper.assert_has_calls([
            mock.call(namespace=mock.sentinel.ns_name),
            mock.call().netns.execute(mock.ANY, extra_ok_codes=[1],
                                      privsep_exec=True)
        ] * 1)

    @mock.patch('eventlet.spawn_n')
    def test_no_ipv6_addr_notif(self, spawn_n):
        ipv6_addr = 'fd00::1'
        ip_lib.send_ip_addr_adv_notif(mock.sentinel.ns_name,
                                      mock.sentinel.iface_name,
                                      ipv6_addr,
                                      3)
        self.assertFalse(spawn_n.called)


class TestAddNamespaceToCmd(base.BaseTestCase):
    def test_add_namespace_to_cmd_with_namespace(self):
        cmd = ['ping', '8.8.8.8']
        self.assertEqual(['ip', 'netns', 'exec', 'tmp'] + cmd,
                         ip_lib.add_namespace_to_cmd(cmd, 'tmp'))

    def test_add_namespace_to_cmd_without_namespace(self):
        cmd = ['ping', '8.8.8.8']
        self.assertEqual(cmd, ip_lib.add_namespace_to_cmd(cmd, None))


class TestSetIpNonlocalBindForHaNamespace(base.BaseTestCase):
    def test_setting_failure(self):
        """Make sure message is formatted correctly."""
        with mock.patch.object(ip_lib, 'set_ip_nonlocal_bind', return_value=1):
            ip_lib.set_ip_nonlocal_bind_for_namespace('foo', value=1)


class TestSysctl(base.BaseTestCase):
    def setUp(self):
        super(TestSysctl, self).setUp()
        self.execute_p = mock.patch.object(ip_lib.IpNetnsCommand, 'execute')
        self.execute = self.execute_p.start()

    def test_disable_ipv6_when_ipv6_globally_enabled(self):
        dev = ip_lib.IPDevice('tap0', 'ns1')
        with mock.patch.object(netutils, 'is_ipv6_enabled', return_value=True):
            dev.disable_ipv6()
            self.execute.assert_called_once_with(
                ['sysctl', '-w', 'net.ipv6.conf.tap0.disable_ipv6=1'],
                log_fail_as_error=True, run_as_root=True, privsep_exec=True)

    def test_disable_ipv6_when_ipv6_globally_disabled(self):
        dev = ip_lib.IPDevice('tap0', 'ns1')
        with mock.patch.object(netutils, 'is_ipv6_enabled',
                               return_value=False):
            dev.disable_ipv6()
            self.assertFalse(self.execute.called)


class TestConntrack(base.BaseTestCase):
    def setUp(self):
        super(TestConntrack, self).setUp()
        self.execute_p = mock.patch.object(ip_lib.IpNetnsCommand, 'execute')
        self.execute = self.execute_p.start()

    def test_delete_socket_conntrack_state(self):
        device = ip_lib.IPDevice('tap0', 'ns1')
        ip_str = '1.1.1.1'
        dport = '3378'
        protocol = 'tcp'
        expect_cmd = ["conntrack", "-D", "-d", ip_str, '-p', protocol,
                      '--dport', dport]
        device.delete_socket_conntrack_state(ip_str, dport, protocol)
        self.execute.assert_called_once_with(expect_cmd, check_exit_code=True,
                                             extra_ok_codes=[1],
                                             privsep_exec=True)


class ParseIpRuleTestCase(base.BaseTestCase):

    BASE_RULE = {
        'family': 2, 'dst_len': 0, 'res2': 0, 'tos': 0, 'res1': 0, 'flags': 0,
        'header': {
            'pid': 18152, 'length': 44, 'flags': 2, 'error': None, 'type': 32,
            'sequence_number': 281},
        'attrs': {'FRA_TABLE': 255, 'FRA_SUPPRESS_PREFIXLEN': 4294967295},
        'table': 255, 'action': 1, 'src_len': 0, 'event': 'RTM_NEWRULE'}

    def setUp(self):
        super(ParseIpRuleTestCase, self).setUp()
        self.rule = copy.deepcopy(self.BASE_RULE)

    def test_parse_priority(self):
        self.rule['attrs']['FRA_PRIORITY'] = 1000
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('1000', parsed_rule['priority'])

    def test_parse_from_ipv4(self):
        self.rule['attrs']['FRA_SRC'] = '192.168.0.1'
        self.rule['src_len'] = 24
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('192.168.0.1/24', parsed_rule['from'])

    def test_parse_from_ipv6(self):
        self.rule['attrs']['FRA_SRC'] = '2001:db8::1'
        self.rule['src_len'] = 64
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 6)
        self.assertEqual('2001:db8::1/64', parsed_rule['from'])

    def test_parse_from_any_ipv4(self):
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('0.0.0.0/0', parsed_rule['from'])

    def test_parse_from_any_ipv6(self):
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 6)
        self.assertEqual('::/0', parsed_rule['from'])

    def test_parse_to_ipv4(self):
        self.rule['attrs']['FRA_DST'] = '192.168.10.1'
        self.rule['dst_len'] = 24
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('192.168.10.1/24', parsed_rule['to'])

    def test_parse_to_ipv6(self):
        self.rule['attrs']['FRA_DST'] = '2001:db8::1'
        self.rule['dst_len'] = 64
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 6)
        self.assertEqual('2001:db8::1/64', parsed_rule['to'])

    def test_parse_to_none(self):
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertIsNone(parsed_rule.get('to'))

    def test_parse_table(self):
        self.rule['attrs']['FRA_TABLE'] = 255
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('local', parsed_rule['table'])
        self.rule['attrs']['FRA_TABLE'] = 254
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('main', parsed_rule['table'])
        self.rule['attrs']['FRA_TABLE'] = 253
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('default', parsed_rule['table'])
        self.rule['attrs']['FRA_TABLE'] = 1000
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('1000', parsed_rule['table'])

    def test_parse_fwmark(self):
        self.rule['attrs']['FRA_FWMARK'] = 1000
        self.rule['attrs']['FRA_FWMASK'] = 10
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('0x3e8/0xa', parsed_rule['fwmark'])

    def test_parse_fwmark_none(self):
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertIsNone(parsed_rule.get('fwmark'))

    def test_parse_iif(self):
        self.rule['attrs']['FRA_IIFNAME'] = 'input_interface_name'
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('input_interface_name', parsed_rule['iif'])

    def test_parse_iif_none(self):
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertIsNone(parsed_rule.get('iif'))

    def test_parse_oif(self):
        self.rule['attrs']['FRA_OIFNAME'] = 'output_interface_name'
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertEqual('output_interface_name', parsed_rule['oif'])

    def test_parse_oif_none(self):
        parsed_rule = ip_lib._parse_ip_rule(self.rule, 4)
        self.assertIsNone(parsed_rule.get('oif'))


class ListIpRulesTestCase(base.BaseTestCase):

    def test_list_ip_rules(self):
        rule1 = {'family': 2, 'src_len': 24, 'action': 1,
                 'attrs': {'FRA_SRC': '10.0.0.1', 'FRA_TABLE': 100}}
        rule2 = {'family': 2, 'src_len': 0, 'action': 6,
                 'attrs': {'FRA_TABLE': 255}}
        rules = [rule1, rule2]
        with mock.patch.object(priv_lib, 'list_ip_rules') as mock_list_rules:
            mock_list_rules.return_value = rules
            retval = ip_lib.list_ip_rules(mock.ANY, 4)
        reference = [
            {'type': 'unicast', 'from': '10.0.0.1/24', 'priority': '0',
             'table': '100'},
            {'type': 'blackhole', 'from': '0.0.0.0/0', 'priority': '0',
             'table': 'local'}]
        self.assertEqual(reference, retval)


class GetDevicesInfoTestCase(base.BaseTestCase):

    DEVICE_LO = {
        'index': 2,
        'attrs': (('IFLA_IFNAME', 'lo'), ('IFLA_OPERSTATE', 'UP'),
                  ('IFLA_LINKMODE', 0), ('IFLA_MTU', 1000),
                  ('IFLA_PROMISCUITY', 0),
                  ('IFLA_ADDRESS', '5a:76:ed:cc:ce:90'),
                  ('IFLA_BROADCAST', 'ff:ff:ff:ff:ff:f0'), )
    }

    DEVICE_DUMMY = {
        'index': 2,
        'attrs': (('IFLA_IFNAME', 'int_01'), ('IFLA_OPERSTATE', 'DOWN'),
                  ('IFLA_LINKMODE', 0), ('IFLA_MTU', 1500),
                  ('IFLA_PROMISCUITY', 0),
                  ('IFLA_ADDRESS', '5a:76:ed:cc:ce:90'),
                  ('IFLA_BROADCAST', 'ff:ff:ff:ff:ff:f0'),
                  ('IFLA_LINKINFO', {
                      'attrs': (('IFLA_INFO_KIND', 'dummy'), )}))
    }
    DEVICE_VLAN = {
        'index': 5,
        'attrs': (('IFLA_IFNAME', 'int_02'), ('IFLA_OPERSTATE', 'DOWN'),
                  ('IFLA_LINKMODE', 0), ('IFLA_MTU', 1400),
                  ('IFLA_PROMISCUITY', 0),
                  ('IFLA_ADDRESS', '5a:76:ed:cc:ce:91'),
                  ('IFLA_BROADCAST', 'ff:ff:ff:ff:ff:f1'),
                  ('IFLA_LINK', 2),
                  ('IFLA_LINKINFO', {'attrs': (
                      ('IFLA_INFO_KIND', 'vlan'),
                      ('IFLA_INFO_DATA', {'attrs': (('IFLA_VLAN_ID', 1000), )})
                  )}))
    }
    DEVICE_VXLAN = {
        'index': 9,
        'attrs': (('IFLA_IFNAME', 'int_03'), ('IFLA_OPERSTATE', 'UP'),
                  ('IFLA_LINKMODE', 0), ('IFLA_MTU', 1300),
                  ('IFLA_PROMISCUITY', 0),
                  ('IFLA_ADDRESS', '5a:76:ed:cc:ce:92'),
                  ('IFLA_BROADCAST', 'ff:ff:ff:ff:ff:f2'),
                  ('IFLA_LINKINFO', {'attrs': (
                      ('IFLA_INFO_KIND', 'vxlan'),
                      ('IFLA_INFO_DATA', {'attrs': (
                          ('IFLA_VXLAN_ID', 1001),
                          ('IFLA_VXLAN_GROUP', '239.1.1.1'),
                          ('IFLA_VXLAN_LINK', 2))})
                  )}))
    }

    DEVICE_VETH = {
        'index': 11,
        'attrs': (('IFLA_IFNAME', 'int_04'), ('IFLA_OPERSTATE', 'UP'),
                  ('IFLA_LINKMODE', 0), ('IFLA_MTU', 900),
                  ('IFLA_PROMISCUITY', 0),
                  ('IFLA_ADDRESS', '5a:76:ed:cc:ce:93'),
                  ('IFLA_BROADCAST', 'ff:ff:ff:ff:ff:f3'),
                  ('IFLA_LINK', 30),
                  ('IFLA_LINKINFO', {
                      'attrs': (('IFLA_INFO_KIND', 'veth'), )}))
    }

    def setUp(self):
        super(GetDevicesInfoTestCase, self).setUp()
        self.mock_getdevs = mock.patch.object(priv_lib,
                                              'get_link_devices').start()

    def test_get_devices_info_lo(self):
        self.mock_getdevs.return_value = (self.DEVICE_LO, )
        ret = ip_lib.get_devices_info('namespace')
        expected = {'index': 2,
                    'name': 'lo',
                    'operstate': 'UP',
                    'linkmode': 0,
                    'mtu': 1000,
                    'promiscuity': 0,
                    'mac': '5a:76:ed:cc:ce:90',
                    'broadcast': 'ff:ff:ff:ff:ff:f0'}
        self.assertEqual(expected, ret[0])

    def test_get_devices_info_dummy(self):
        self.mock_getdevs.return_value = (self.DEVICE_DUMMY, )
        ret = ip_lib.get_devices_info('namespace')
        expected = {'index': 2,
                    'name': 'int_01',
                    'operstate': 'DOWN',
                    'linkmode': 0,
                    'mtu': 1500,
                    'promiscuity': 0,
                    'mac': '5a:76:ed:cc:ce:90',
                    'broadcast': 'ff:ff:ff:ff:ff:f0',
                    'kind': 'dummy'}
        self.assertEqual(expected, ret[0])

    def test_get_devices_info_vlan(self):
        self.mock_getdevs.return_value = (self.DEVICE_VLAN, self.DEVICE_DUMMY)
        ret = ip_lib.get_devices_info('namespace')
        expected = {'index': 5,
                    'name': 'int_02',
                    'operstate': 'DOWN',
                    'linkmode': 0,
                    'mtu': 1400,
                    'promiscuity': 0,
                    'mac': '5a:76:ed:cc:ce:91',
                    'broadcast': 'ff:ff:ff:ff:ff:f1',
                    'kind': 'vlan',
                    'vlan_id': 1000,
                    'parent_index': 2,
                    'parent_name': 'int_01'}
        for device in (device for device in ret if device['kind'] == 'vlan'):
            self.assertEqual(expected, device)
            break
        else:
            self.fail('No VLAN device found')

    def test_get_devices_info_vxlan(self):
        self.mock_getdevs.return_value = (self.DEVICE_VXLAN, self.DEVICE_DUMMY)
        ret = ip_lib.get_devices_info('namespace')
        expected = {'index': 9,
                    'name': 'int_03',
                    'operstate': 'UP',
                    'linkmode': 0,
                    'mtu': 1300,
                    'promiscuity': 0,
                    'mac': '5a:76:ed:cc:ce:92',
                    'broadcast': 'ff:ff:ff:ff:ff:f2',
                    'kind': 'vxlan',
                    'vxlan_id': 1001,
                    'vxlan_group': '239.1.1.1',
                    'vxlan_link_index': 2,
                    'vxlan_link_name': 'int_01'}
        for device in (device for device in ret if device['kind'] == 'vxlan'):
            self.assertEqual(expected, device)
            break
        else:
            self.fail('No VXLAN device found')

    def test_get_devices_info_veth(self):
        self.mock_getdevs.return_value = (self.DEVICE_VETH, self.DEVICE_DUMMY)
        ret = ip_lib.get_devices_info('namespace')
        expected = {'index': 11,
                    'name': 'int_04',
                    'operstate': 'UP',
                    'linkmode': 0,
                    'mtu': 900,
                    'promiscuity': 0,
                    'mac': '5a:76:ed:cc:ce:93',
                    'broadcast': 'ff:ff:ff:ff:ff:f3',
                    'kind': 'veth',
                    'parent_index': 30}
        for device in (device for device in ret if device['kind'] == 'veth'):
            self.assertEqual(expected, device)
            break
        else:
            self.fail('No VETH device found')
