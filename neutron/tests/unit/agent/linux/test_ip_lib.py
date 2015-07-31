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

import mock
import netaddr
import testtools

from neutron.agent.common import utils  # noqa
from neutron.agent.linux import ip_lib
from neutron.common import exceptions
from neutron.tests import base

NETNS_SAMPLE = [
    '12345678-1234-5678-abcd-1234567890ab',
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'cccccccc-cccc-cccc-cccc-cccccccccccc']

LINK_SAMPLE = [
    '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN \\'
    'link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0',
    '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP '
    'qlen 1000\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff'
    '\    alias openvswitch',
    '3: br-int: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN '
    '\    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff promiscuity 0',
    '4: gw-ddc717df-49: <BROADCAST,MULTICAST> mtu 1500 qdisc noop '
    'state DOWN \    link/ether fe:dc:ba:fe:dc:ba brd ff:ff:ff:ff:ff:ff '
    'promiscuity 0',
    '5: foo:foo: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state '
    'UP qlen 1000\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff '
    'promiscuity 0',
    '6: foo@foo: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state '
    'UP qlen 1000\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff '
    'promiscuity 0',
    '7: foo:foo@foo: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq '
    'state UP qlen 1000'
    '\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff promiscuity 0',
    '8: foo@foo:foo: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq '
    'state UP qlen 1000'
    '\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff promiscuity 0',
    '9: bar.9@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc '
    ' noqueue master brq0b24798c-07 state UP mode DEFAULT'
    '\    link/ether ab:04:49:b6:ab:a0 brd ff:ff:ff:ff:ff:ff promiscuity 0'
    '\    vlan protocol 802.1q id 9 <REORDER_HDR>',
    '10: bar@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc '
    ' noqueue master brq0b24798c-07 state UP mode DEFAULT'
    '\    link/ether ab:04:49:b6:ab:a0 brd ff:ff:ff:ff:ff:ff promiscuity 0'
    '\    vlan protocol 802.1Q id 10 <REORDER_HDR>',
    '11: bar:bar@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq '
    'state UP qlen 1000'
    '\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff promiscuity 0'
    '\    vlan id 11 <REORDER_HDR>',
    '12: bar@bar@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq '
    'state UP qlen 1000'
    '\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff promiscuity 0'
    '\    vlan id 12 <REORDER_HDR>',
    '13: bar:bar@bar@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 '
    'qdisc mq state UP qlen 1000'
    '\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff promiscuity 0'
    '\    vlan protocol 802.1q id 13 <REORDER_HDR>',
    '14: bar@bar:bar@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 '
    'qdisc mq state UP qlen 1000'
    '\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff promiscuity 0'
    '\    vlan protocol 802.1Q id 14 <REORDER_HDR>']

ADDR_SAMPLE = ("""
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP qlen 1000
    link/ether dd:cc:aa:b9:76:ce brd ff:ff:ff:ff:ff:ff
    inet 172.16.77.240/24 brd 172.16.77.255 scope global eth0
    inet6 2001:470:9:1224:5595:dd51:6ba2:e788/64 scope global temporary dynamic
       valid_lft 14187sec preferred_lft 3387sec
    inet6 fe80::3023:39ff:febc:22ae/64 scope link tentative
        valid_lft forever preferred_lft forever
    inet6 fe80::3023:39ff:febc:22af/64 scope link tentative dadfailed
        valid_lft forever preferred_lft forever
    inet6 2001:470:9:1224:fd91:272:581e:3a32/64 scope global temporary """
               """deprecated dynamic
       valid_lft 14187sec preferred_lft 0sec
    inet6 2001:470:9:1224:4508:b885:5fb:740b/64 scope global temporary """
               """deprecated dynamic
       valid_lft 14187sec preferred_lft 0sec
    inet6 2001:470:9:1224:dfcc:aaff:feb9:76ce/64 scope global dynamic
       valid_lft 14187sec preferred_lft 3387sec
    inet6 fe80::dfcc:aaff:feb9:76ce/64 scope link
       valid_lft forever preferred_lft forever
""")

ADDR_SAMPLE2 = ("""
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP qlen 1000
    link/ether dd:cc:aa:b9:76:ce brd ff:ff:ff:ff:ff:ff
    inet 172.16.77.240/24 scope global eth0
    inet6 2001:470:9:1224:5595:dd51:6ba2:e788/64 scope global temporary dynamic
       valid_lft 14187sec preferred_lft 3387sec
    inet6 fe80::3023:39ff:febc:22ae/64 scope link tentative
        valid_lft forever preferred_lft forever
    inet6 fe80::3023:39ff:febc:22af/64 scope link tentative dadfailed
        valid_lft forever preferred_lft forever
    inet6 2001:470:9:1224:fd91:272:581e:3a32/64 scope global temporary """
                """deprecated dynamic
       valid_lft 14187sec preferred_lft 0sec
    inet6 2001:470:9:1224:4508:b885:5fb:740b/64 scope global temporary """
                """deprecated dynamic
       valid_lft 14187sec preferred_lft 0sec
    inet6 2001:470:9:1224:dfcc:aaff:feb9:76ce/64 scope global dynamic
       valid_lft 14187sec preferred_lft 3387sec
    inet6 fe80::dfcc:aaff:feb9:76ce/64 scope link
       valid_lft forever preferred_lft forever
""")

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

RULE_V4_SAMPLE = ("""
0:      from all lookup local
32766:  from all lookup main
32767:  from all lookup default
101:    from 192.168.45.100 lookup 2
""")

RULE_V6_SAMPLE = ("""
0:      from all lookup local
32766:  from all lookup main
32767:  from all lookup default
201:    from 2001:db8::1 lookup 3
""")


class TestSubProcessBase(base.BaseTestCase):
    def setUp(self):
        super(TestSubProcessBase, self).setUp()
        self.execute_p = mock.patch('neutron.agent.common.utils.execute')
        self.execute = self.execute_p.start()

    def test_execute_wrapper(self):
        ip_lib.SubProcessBase._execute(['o'], 'link', ('list',),
                                       run_as_root=True)

        self.execute.assert_called_once_with(['ip', '-o', 'link', 'list'],
                                             run_as_root=True,
                                             log_fail_as_error=True)

    def test_execute_wrapper_int_options(self):
        ip_lib.SubProcessBase._execute([4], 'link', ('list',))

        self.execute.assert_called_once_with(['ip', '-4', 'link', 'list'],
                                             run_as_root=False,
                                             log_fail_as_error=True)

    def test_execute_wrapper_no_options(self):
        ip_lib.SubProcessBase._execute([], 'link', ('list',))

        self.execute.assert_called_once_with(['ip', 'link', 'list'],
                                             run_as_root=False,
                                             log_fail_as_error=True)

    def test_run_no_namespace(self):
        base = ip_lib.SubProcessBase()
        base._run([], 'link', ('list',))
        self.execute.assert_called_once_with(['ip', 'link', 'list'],
                                             run_as_root=False,
                                             log_fail_as_error=True)

    def test_run_namespace(self):
        base = ip_lib.SubProcessBase(namespace='ns')
        base._run([], 'link', ('list',))
        self.execute.assert_called_once_with(['ip', 'netns', 'exec', 'ns',
                                              'ip', 'link', 'list'],
                                             run_as_root=True,
                                             log_fail_as_error=True)

    def test_as_root_namespace(self):
        base = ip_lib.SubProcessBase(namespace='ns')
        base._as_root([], 'link', ('list',))
        self.execute.assert_called_once_with(['ip', 'netns', 'exec', 'ns',
                                              'ip', 'link', 'list'],
                                             run_as_root=True,
                                             log_fail_as_error=True)


class TestIpWrapper(base.BaseTestCase):
    def setUp(self):
        super(TestIpWrapper, self).setUp()
        self.execute_p = mock.patch.object(ip_lib.IPWrapper, '_execute')
        self.execute = self.execute_p.start()

    @mock.patch('os.path.islink')
    @mock.patch('os.listdir', return_value=['lo'])
    def test_get_devices(self, mocked_listdir, mocked_islink):
        retval = ip_lib.IPWrapper().get_devices()
        mocked_islink.assert_called_once_with('/sys/class/net/lo')
        self.assertEqual(retval, [ip_lib.IPDevice('lo')])

    @mock.patch('neutron.agent.common.utils.execute')
    def test_get_devices_namespaces(self, mocked_execute):
        fake_str = mock.Mock()
        fake_str.split.return_value = ['lo']
        mocked_execute.return_value = fake_str
        retval = ip_lib.IPWrapper(namespace='foo').get_devices()
        mocked_execute.assert_called_once_with(
                ['ip', 'netns', 'exec', 'foo', 'find', '/sys/class/net',
                 '-maxdepth', '1', '-type', 'l', '-printf', '%f '],
                run_as_root=True, log_fail_as_error=True)
        self.assertTrue(fake_str.split.called)
        self.assertEqual(retval, [ip_lib.IPDevice('lo', namespace='foo')])

    def test_get_namespaces(self):
        self.execute.return_value = '\n'.join(NETNS_SAMPLE)
        retval = ip_lib.IPWrapper.get_namespaces()
        self.assertEqual(retval,
                         ['12345678-1234-5678-abcd-1234567890ab',
                          'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
                          'cccccccc-cccc-cccc-cccc-cccccccccccc'])

        self.execute.assert_called_once_with([], 'netns', ('list',))

    def test_add_tuntap(self):
        ip_lib.IPWrapper().add_tuntap('tap0')
        self.execute.assert_called_once_with([], 'tuntap',
                                             ('add', 'tap0', 'mode', 'tap'),
                                             run_as_root=True, namespace=None,
                                             log_fail_as_error=True)

    def test_add_veth(self):
        ip_lib.IPWrapper().add_veth('tap0', 'tap1')
        self.execute.assert_called_once_with([], 'link',
                                             ('add', 'tap0', 'type', 'veth',
                                              'peer', 'name', 'tap1'),
                                             run_as_root=True, namespace=None,
                                             log_fail_as_error=True)

    def test_del_veth(self):
        ip_lib.IPWrapper().del_veth('fpr-1234')
        self.execute.assert_called_once_with([], 'link',
                                             ('del', 'fpr-1234'),
                                             run_as_root=True, namespace=None,
                                             log_fail_as_error=True)

    def test_add_veth_with_namespaces(self):
        ns2 = 'ns2'
        with mock.patch.object(ip_lib.IPWrapper, 'ensure_namespace') as en:
            ip_lib.IPWrapper().add_veth('tap0', 'tap1', namespace2=ns2)
            en.assert_has_calls([mock.call(ns2)])
        self.execute.assert_called_once_with([], 'link',
                                             ('add', 'tap0', 'type', 'veth',
                                              'peer', 'name', 'tap1',
                                              'netns', ns2),
                                             run_as_root=True, namespace=None,
                                             log_fail_as_error=True)

    def test_get_device(self):
        dev = ip_lib.IPWrapper(namespace='ns').device('eth0')
        self.assertEqual(dev.namespace, 'ns')
        self.assertEqual(dev.name, 'eth0')

    def test_ensure_namespace(self):
        with mock.patch.object(ip_lib, 'IPDevice') as ip_dev:
            ip = ip_lib.IPWrapper()
            with mock.patch.object(ip.netns, 'exists') as ns_exists:
                with mock.patch('neutron.agent.common.utils.execute'):
                    ns_exists.return_value = False
                    ip.ensure_namespace('ns')
                    self.execute.assert_has_calls(
                        [mock.call([], 'netns', ('add', 'ns'),
                                   run_as_root=True, namespace=None,
                                   log_fail_as_error=True)])
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
            get_devices.assert_called_once_with(exclude_loopback=True)

    def test_namespace_is_empty(self):
        ip = ip_lib.IPWrapper(namespace='ns')
        with mock.patch.object(ip, 'get_devices') as get_devices:
            get_devices.return_value = [mock.Mock()]

            self.assertFalse(ip.namespace_is_empty())
            get_devices.assert_called_once_with(exclude_loopback=True)

    def test_garbage_collect_namespace_does_not_exist(self):
        with mock.patch.object(ip_lib, 'IpNetnsCommand') as ip_ns_cmd_cls:
            ip_ns_cmd_cls.return_value.exists.return_value = False
            ip = ip_lib.IPWrapper(namespace='ns')
            with mock.patch.object(ip, 'namespace_is_empty') as mock_is_empty:

                self.assertFalse(ip.garbage_collect_namespace())
                ip_ns_cmd_cls.assert_has_calls([mock.call().exists('ns')])
                self.assertNotIn(mock.call().delete('ns'),
                                 ip_ns_cmd_cls.return_value.mock_calls)
                self.assertEqual(mock_is_empty.mock_calls, [])

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

    def test_add_vxlan_valid_port_length(self):
        retval = ip_lib.IPWrapper().add_vxlan('vxlan0', 'vni0',
                                              group='group0',
                                              dev='dev0', ttl='ttl0',
                                              tos='tos0',
                                              local='local0', proxy=True,
                                              port=('1', '2'))
        self.assertIsInstance(retval, ip_lib.IPDevice)
        self.assertEqual(retval.name, 'vxlan0')
        self.execute.assert_called_once_with([], 'link',
                                             ['add', 'vxlan0', 'type',
                                              'vxlan', 'id', 'vni0', 'group',
                                              'group0', 'dev', 'dev0',
                                              'ttl', 'ttl0', 'tos', 'tos0',
                                              'local', 'local0', 'proxy',
                                              'port', '1', '2'],
                                             run_as_root=True, namespace=None,
                                             log_fail_as_error=True)

    def test_add_vxlan_invalid_port_length(self):
        wrapper = ip_lib.IPWrapper()
        self.assertRaises(exceptions.NetworkVxlanPortRangeError,
                          wrapper.add_vxlan, 'vxlan0', 'vni0', group='group0',
                          dev='dev0', ttl='ttl0', tos='tos0',
                          local='local0', proxy=True,
                          port=('1', '2', '3'))

    def test_add_device_to_namespace(self):
        dev = mock.Mock()
        ip_lib.IPWrapper(namespace='ns').add_device_to_namespace(dev)
        dev.assert_has_calls([mock.call.link.set_netns('ns')])

    def test_add_device_to_namespace_is_none(self):
        dev = mock.Mock()
        ip_lib.IPWrapper().add_device_to_namespace(dev)
        self.assertEqual(dev.mock_calls, [])


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


class TestIPCommandBase(base.BaseTestCase):
    def setUp(self):
        super(TestIPCommandBase, self).setUp()
        self.ip = mock.Mock()
        self.ip.namespace = 'namespace'
        self.ip_cmd = ip_lib.IpCommandBase(self.ip)
        self.ip_cmd.COMMAND = 'foo'

    def test_run(self):
        self.ip_cmd._run([], ('link', 'show'))
        self.ip.assert_has_calls([mock.call._run([], 'foo', ('link', 'show'))])

    def test_run_with_options(self):
        self.ip_cmd._run(['o'], ('link'))
        self.ip.assert_has_calls([mock.call._run(['o'], 'foo', ('link'))])

    def test_as_root_namespace_false(self):
        self.ip_cmd._as_root([], ('link'))
        self.ip.assert_has_calls(
            [mock.call._as_root([],
                                'foo',
                                ('link'),
                                use_root_namespace=False)])

    def test_as_root_namespace_true(self):
        self.ip_cmd._as_root([], ('link'), use_root_namespace=True)
        self.ip.assert_has_calls(
            [mock.call._as_root([],
                                'foo',
                                ('link'),
                                use_root_namespace=True)])

    def test_as_root_namespace_true_with_options(self):
        self.ip_cmd._as_root('o', 'link', use_root_namespace=True)
        self.ip.assert_has_calls(
            [mock.call._as_root('o',
                                'foo',
                                ('link'),
                                use_root_namespace=True)])


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
        self.parent.assert_has_calls([
            mock.call._run(options, self.command, args)])

    def _assert_sudo(self, options, args, use_root_namespace=False):
        self.parent.assert_has_calls(
            [mock.call._as_root(options, self.command, args,
                                use_root_namespace=use_root_namespace)])


class TestIpRuleCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpRuleCommand, self).setUp()
        self.parent._as_root.return_value = ''
        self.command = 'rule'
        self.rule_cmd = ip_lib.IpRuleCommand(self.parent)

    def _test_add_rule(self, ip, table, priority):
        ip_version = netaddr.IPNetwork(ip).version
        self.rule_cmd.add(ip, table=table, priority=priority)
        self._assert_sudo([ip_version], (['show']))
        self._assert_sudo([ip_version], ('add', 'from', ip,
                                         'priority', priority, 'table', table))

    def _test_add_rule_exists(self, ip, table, priority, output):
        self.parent._as_root.return_value = output
        ip_version = netaddr.IPNetwork(ip).version
        self.rule_cmd.add(ip, table=table, priority=priority)
        self._assert_sudo([ip_version], (['show']))

    def _test_delete_rule(self, ip, table, priority):
        ip_version = netaddr.IPNetwork(ip).version
        self.rule_cmd.delete(ip, table=table, priority=priority)
        self._assert_sudo([ip_version],
                          ('del', 'priority', priority,
                           'table', table))

    def test__parse_line(self):
        def test(ip_version, line, expected):
            actual = self.rule_cmd._parse_line(ip_version, line)
            self.assertEqual(expected, actual)

        test(4, "4030201:\tfrom 1.2.3.4/24 lookup 10203040",
             {'from': '1.2.3.4/24',
              'table': '10203040',
              'priority': '4030201'})
        test(6, "1024:    from all iif qg-c43b1928-48 lookup noscope",
             {'priority': '1024',
              'from': '::/0',
              'iif': 'qg-c43b1928-48',
              'table': 'noscope'})

    def test_add_rule_v4(self):
        self._test_add_rule('192.168.45.100', 2, 100)

    def test_add_rule_v4_exists(self):
        self._test_add_rule_exists('192.168.45.100', 2, 101, RULE_V4_SAMPLE)

    def test_add_rule_v6(self):
        self._test_add_rule('2001:db8::1', 3, 200)

    def test_add_rule_v6_exists(self):
        self._test_add_rule_exists('2001:db8::1', 3, 201, RULE_V6_SAMPLE)

    def test_delete_rule_v4(self):
        self._test_delete_rule('192.168.45.100', 2, 100)

    def test_delete_rule_v6(self):
        self._test_delete_rule('2001:db8::1', 3, 200)


class TestIpLinkCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpLinkCommand, self).setUp()
        self.parent._run.return_value = LINK_SAMPLE[1]
        self.command = 'link'
        self.link_cmd = ip_lib.IpLinkCommand(self.parent)

    def test_set_address(self):
        self.link_cmd.set_address('aa:bb:cc:dd:ee:ff')
        self._assert_sudo([], ('set', 'eth0', 'address', 'aa:bb:cc:dd:ee:ff'))

    def test_set_mtu(self):
        self.link_cmd.set_mtu(1500)
        self._assert_sudo([], ('set', 'eth0', 'mtu', 1500))

    def test_set_up(self):
        observed = self.link_cmd.set_up()
        self.assertEqual(self.parent._as_root.return_value, observed)
        self._assert_sudo([], ('set', 'eth0', 'up'))

    def test_set_down(self):
        observed = self.link_cmd.set_down()
        self.assertEqual(self.parent._as_root.return_value, observed)
        self._assert_sudo([], ('set', 'eth0', 'down'))

    def test_set_netns(self):
        self.link_cmd.set_netns('foo')
        self._assert_sudo([], ('set', 'eth0', 'netns', 'foo'))
        self.assertEqual(self.parent.namespace, 'foo')

    def test_set_name(self):
        self.link_cmd.set_name('tap1')
        self._assert_sudo([], ('set', 'eth0', 'name', 'tap1'))
        self.assertEqual(self.parent.name, 'tap1')

    def test_set_alias(self):
        self.link_cmd.set_alias('openvswitch')
        self._assert_sudo([], ('set', 'eth0', 'alias', 'openvswitch'))

    def test_delete(self):
        self.link_cmd.delete()
        self._assert_sudo([], ('delete', 'eth0'))

    def test_address_property(self):
        self.parent._execute = mock.Mock(return_value=LINK_SAMPLE[1])
        self.assertEqual(self.link_cmd.address, 'cc:dd:ee:ff:ab:cd')

    def test_mtu_property(self):
        self.parent._execute = mock.Mock(return_value=LINK_SAMPLE[1])
        self.assertEqual(self.link_cmd.mtu, 1500)

    def test_qdisc_property(self):
        self.parent._execute = mock.Mock(return_value=LINK_SAMPLE[1])
        self.assertEqual(self.link_cmd.qdisc, 'mq')

    def test_qlen_property(self):
        self.parent._execute = mock.Mock(return_value=LINK_SAMPLE[1])
        self.assertEqual(self.link_cmd.qlen, 1000)

    def test_alias_property(self):
        self.parent._execute = mock.Mock(return_value=LINK_SAMPLE[1])
        self.assertEqual(self.link_cmd.alias, 'openvswitch')

    def test_state_property(self):
        self.parent._execute = mock.Mock(return_value=LINK_SAMPLE[1])
        self.assertEqual(self.link_cmd.state, 'UP')

    def test_settings_property(self):
        expected = {'mtu': 1500,
                    'qlen': 1000,
                    'state': 'UP',
                    'qdisc': 'mq',
                    'brd': 'ff:ff:ff:ff:ff:ff',
                    'link/ether': 'cc:dd:ee:ff:ab:cd',
                    'alias': 'openvswitch'}
        self.parent._execute = mock.Mock(return_value=LINK_SAMPLE[1])
        self.assertEqual(self.link_cmd.attributes, expected)
        self._assert_call(['o'], ('show', 'eth0'))


class TestIpAddrCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpAddrCommand, self).setUp()
        self.parent.name = 'tap0'
        self.command = 'addr'
        self.addr_cmd = ip_lib.IpAddrCommand(self.parent)

    def test_add_address(self):
        self.addr_cmd.add('192.168.45.100/24')
        self._assert_sudo([4],
                          ('add', '192.168.45.100/24',
                           'scope', 'global',
                           'dev', 'tap0',
                           'brd', '192.168.45.255'))

    def test_add_address_scoped(self):
        self.addr_cmd.add('192.168.45.100/24', scope='link')
        self._assert_sudo([4],
                          ('add', '192.168.45.100/24',
                           'scope', 'link',
                           'dev', 'tap0',
                           'brd', '192.168.45.255'))

    def test_del_address(self):
        self.addr_cmd.delete('192.168.45.100/24')
        self._assert_sudo([4],
                          ('del', '192.168.45.100/24', 'dev', 'tap0'))

    def test_flush(self):
        self.addr_cmd.flush(6)
        self._assert_sudo([6], ('flush', 'tap0'))

    def test_list(self):
        expected = [
            dict(scope='global', dadfailed=False, tentative=False,
                 dynamic=False, cidr='172.16.77.240/24'),
            dict(scope='global', dadfailed=False, tentative=False,
                 dynamic=True, cidr='2001:470:9:1224:5595:dd51:6ba2:e788/64'),
            dict(scope='link', dadfailed=False, tentative=True,
                 dynamic=False, cidr='fe80::3023:39ff:febc:22ae/64'),
            dict(scope='link', dadfailed=True, tentative=True,
                 dynamic=False, cidr='fe80::3023:39ff:febc:22af/64'),
            dict(scope='global', dadfailed=False, tentative=False,
                 dynamic=True, cidr='2001:470:9:1224:fd91:272:581e:3a32/64'),
            dict(scope='global', dadfailed=False, tentative=False,
                 dynamic=True, cidr='2001:470:9:1224:4508:b885:5fb:740b/64'),
            dict(scope='global', dadfailed=False, tentative=False,
                 dynamic=True, cidr='2001:470:9:1224:dfcc:aaff:feb9:76ce/64'),
            dict(scope='link', dadfailed=False, tentative=False,
                 dynamic=False, cidr='fe80::dfcc:aaff:feb9:76ce/64')]

        test_cases = [ADDR_SAMPLE, ADDR_SAMPLE2]

        for test_case in test_cases:
            self.parent._run = mock.Mock(return_value=test_case)
            self.assertEqual(expected, self.addr_cmd.list())
            self._assert_call([], ('show', 'tap0'))

    def test_wait_until_address_ready(self):
        self.parent._run.return_value = ADDR_SAMPLE
        # this address is not tentative or failed so it should return
        self.assertIsNone(self.addr_cmd.wait_until_address_ready(
            '2001:470:9:1224:fd91:272:581e:3a32'))

    def test_wait_until_address_ready_non_existent_address(self):
        self.addr_cmd.list = mock.Mock(return_value=[])
        with testtools.ExpectedException(ip_lib.AddressNotReady):
            self.addr_cmd.wait_until_address_ready('abcd::1234')

    def test_wait_until_address_ready_timeout(self):
        tentative_address = 'fe80::3023:39ff:febc:22ae'
        self.addr_cmd.list = mock.Mock(return_value=[
            dict(scope='link', dadfailed=False, tentative=True, dynamic=False,
                 cidr=tentative_address + '/64')])
        with testtools.ExpectedException(ip_lib.AddressNotReady):
            self.addr_cmd.wait_until_address_ready(tentative_address,
                                                   wait_time=1)

    def test_list_filtered(self):
        expected = [
            dict(scope='global', tentative=False, dadfailed=False,
                 dynamic=False, cidr='172.16.77.240/24')]

        test_cases = [ADDR_SAMPLE, ADDR_SAMPLE2]

        for test_case in test_cases:
            output = '\n'.join(test_case.split('\n')[0:4])
            self.parent._run.return_value = output
            self.assertEqual(self.addr_cmd.list('global',
                             filters=['permanent']), expected)
            self._assert_call([], ('show', 'tap0', 'permanent', 'scope',
                              'global'))


class TestIpRouteCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpRouteCommand, self).setUp()
        self.parent.name = 'eth0'
        self.command = 'route'
        self.route_cmd = ip_lib.IpRouteCommand(self.parent)
        self.ip_version = 4
        self.table = 14
        self.metric = 100
        self.cidr = '192.168.45.100/24'
        self.ip = '10.0.0.1'
        self.gateway = '192.168.45.100'
        self.test_cases = [{'sample': GATEWAY_SAMPLE1,
                            'expected': {'gateway': '10.35.19.254',
                                         'metric': 100}},
                           {'sample': GATEWAY_SAMPLE2,
                            'expected': {'gateway': '10.35.19.254',
                                         'metric': 100}},
                           {'sample': GATEWAY_SAMPLE3,
                            'expected': None},
                           {'sample': GATEWAY_SAMPLE4,
                            'expected': {'gateway': '10.35.19.254'}},
                           {'sample': GATEWAY_SAMPLE5,
                            'expected': {'gateway': '192.168.99.1'}},
                           {'sample': GATEWAY_SAMPLE6,
                            'expected': {'gateway': '192.168.99.1',
                                         'metric': 100}},
                           {'sample': GATEWAY_SAMPLE7,
                            'expected': {'metric': 1}}]

    def test_add_gateway(self):
        self.route_cmd.add_gateway(self.gateway, self.metric, self.table)
        self._assert_sudo([self.ip_version],
                          ('replace', 'default',
                           'via', self.gateway,
                           'metric', self.metric,
                           'dev', self.parent.name,
                           'table', self.table))

    def test_add_gateway_subtable(self):
        self.route_cmd.table(self.table).add_gateway(self.gateway, self.metric)
        self._assert_sudo([self.ip_version],
                          ('replace', 'default',
                           'via', self.gateway,
                           'metric', self.metric,
                           'dev', self.parent.name,
                           'table', self.table))

    def test_del_gateway_success(self):
        self.route_cmd.delete_gateway(self.gateway, table=self.table)
        self._assert_sudo([self.ip_version],
                          ('del', 'default',
                           'via', self.gateway,
                           'dev', self.parent.name,
                           'table', self.table))

    def test_del_gateway_success_subtable(self):
        self.route_cmd.table(table=self.table).delete_gateway(self.gateway)
        self._assert_sudo([self.ip_version],
                          ('del', 'default',
                           'via', self.gateway,
                           'dev', self.parent.name,
                           'table', self.table))

    def test_del_gateway_cannot_find_device(self):
        self.parent._as_root.side_effect = RuntimeError("Cannot find device")

        exc = self.assertRaises(exceptions.DeviceNotFoundError,
                          self.route_cmd.delete_gateway,
                          self.gateway, table=self.table)
        self.assertIn(self.parent.name, str(exc))

    def test_del_gateway_other_error(self):
        self.parent._as_root.side_effect = RuntimeError()

        self.assertRaises(RuntimeError, self.route_cmd.delete_gateway,
                          self.gateway, table=self.table)

    def test_get_gateway(self):
        for test_case in self.test_cases:
            self.parent._run = mock.Mock(return_value=test_case['sample'])
            self.assertEqual(self.route_cmd.get_gateway(),
                             test_case['expected'])

    def test_pullup_route(self):
        # NOTE(brian-haley) Currently we do not have any IPv6-specific usecase
        # for pullup_route, hence skipping. Revisit, if required, in future.
        if self.ip_version == 6:
            return
        # interface is not the first in the list - requires
        # deleting and creating existing entries
        output = [DEVICE_ROUTE_SAMPLE, SUBNET_SAMPLE1]

        def pullup_side_effect(self, *args):
            result = output.pop(0)
            return result

        self.parent._run = mock.Mock(side_effect=pullup_side_effect)
        self.route_cmd.pullup_route('tap1d7888a7-10', ip_version=4)
        self._assert_sudo([4], ('del', '10.0.0.0/24', 'dev', 'qr-23380d11-d2'))
        self._assert_sudo([4], ('append', '10.0.0.0/24', 'proto', 'kernel',
                                'src', '10.0.0.1', 'dev', 'qr-23380d11-d2'))

    def test_pullup_route_first(self):
        # NOTE(brian-haley) Currently we do not have any IPv6-specific usecase
        # for pullup_route, hence skipping. Revisit, if required, in future.
        if self.ip_version == 6:
            return
        # interface is first in the list - no changes
        output = [DEVICE_ROUTE_SAMPLE, SUBNET_SAMPLE2]

        def pullup_side_effect(self, *args):
            result = output.pop(0)
            return result

        self.parent._run = mock.Mock(side_effect=pullup_side_effect)
        self.route_cmd.pullup_route('tap1d7888a7-10', ip_version=4)
        # Check two calls - device get and subnet get
        self.assertEqual(len(self.parent._run.mock_calls), 2)

    def test_add_route(self):
        self.route_cmd.add_route(self.cidr, self.ip, self.table)
        self._assert_sudo([self.ip_version],
                          ('replace', self.cidr,
                           'via', self.ip,
                           'dev', self.parent.name,
                           'table', self.table))

    def test_delete_route(self):
        self.route_cmd.delete_route(self.cidr, self.ip, self.table)
        self._assert_sudo([self.ip_version],
                          ('del', self.cidr,
                           'via', self.ip,
                           'dev', self.parent.name,
                           'table', self.table))

    def test_list_onlink_routes_subtable(self):
        self.parent._run.return_value = (
            "10.0.0.0/22\n"
            "172.24.4.0/24 proto kernel src 172.24.4.2\n")
        routes = self.route_cmd.table(self.table).list_onlink_routes(
            self.ip_version)
        self.assertEqual(['10.0.0.0/22'], routes)
        self._assert_call([self.ip_version],
                          ('list', 'dev', self.parent.name, 'scope', 'link',
                           'table', self.table))

    def test_add_onlink_route_subtable(self):
        self.route_cmd.table(self.table).add_onlink_route(self.cidr)
        self._assert_sudo([self.ip_version],
                          ('replace', self.cidr,
                           'dev', self.parent.name,
                           'scope', 'link',
                           'table', self.table))

    def test_delete_onlink_route_subtable(self):
        self.route_cmd.table(self.table).delete_onlink_route(self.cidr)
        self._assert_sudo([self.ip_version],
                          ('del', self.cidr,
                           'dev', self.parent.name,
                           'scope', 'link',
                           'table', self.table))


class TestIPv6IpRouteCommand(TestIpRouteCommand):
    def setUp(self):
        super(TestIPv6IpRouteCommand, self).setUp()
        self.ip_version = 6
        self.cidr = '2001:db8::/64'
        self.ip = '2001:db8::100'
        self.gateway = '2001:db8::1'
        self.test_cases = [{'sample': IPv6_GATEWAY_SAMPLE1,
                            'expected':
                            {'gateway': '2001:470:9:1224:4508:b885:5fb:740b',
                             'metric': 100}},
                           {'sample': IPv6_GATEWAY_SAMPLE2,
                            'expected':
                            {'gateway': '2001:470:9:1224:4508:b885:5fb:740b',
                             'metric': 100}},
                           {'sample': IPv6_GATEWAY_SAMPLE3,
                            'expected': None},
                           {'sample': IPv6_GATEWAY_SAMPLE4,
                            'expected':
                            {'gateway': 'fe80::dfcc:aaff:feb9:76ce'}},
                           {'sample': IPv6_GATEWAY_SAMPLE5,
                            'expected':
                            {'gateway': '2001:470:9:1224:4508:b885:5fb:740b',
                             'metric': 1024}}]


class TestIpNetnsCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpNetnsCommand, self).setUp()
        self.command = 'netns'
        self.netns_cmd = ip_lib.IpNetnsCommand(self.parent)

    def test_add_namespace(self):
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            ns = self.netns_cmd.add('ns')
            self._assert_sudo([], ('add', 'ns'), use_root_namespace=True)
            self.assertEqual(ns.namespace, 'ns')
            execute.assert_called_once_with(
                ['ip', 'netns', 'exec', 'ns',
                 'sysctl', '-w', 'net.ipv4.conf.all.promote_secondaries=1'],
                run_as_root=True, check_exit_code=True, extra_ok_codes=None)

    def test_delete_namespace(self):
        with mock.patch('neutron.agent.common.utils.execute'):
            self.netns_cmd.delete('ns')
            self._assert_sudo([], ('delete', 'ns'), use_root_namespace=True)

    def test_namespace_exists_use_helper(self):
        self.config(group='AGENT', use_helper_for_ns_read=True)
        retval = '\n'.join(NETNS_SAMPLE)
        # need another instance to avoid mocking
        netns_cmd = ip_lib.IpNetnsCommand(ip_lib.SubProcessBase())
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            execute.return_value = retval
            self.assertTrue(
                netns_cmd.exists('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'))
            execute.assert_called_once_with(['ip', '-o', 'netns', 'list'],
                                            run_as_root=True,
                                            log_fail_as_error=True)

    def test_namespace_doest_not_exist_no_helper(self):
        self.config(group='AGENT', use_helper_for_ns_read=False)
        retval = '\n'.join(NETNS_SAMPLE)
        # need another instance to avoid mocking
        netns_cmd = ip_lib.IpNetnsCommand(ip_lib.SubProcessBase())
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            execute.return_value = retval
            self.assertFalse(
                netns_cmd.exists('bbbbbbbb-1111-2222-3333-bbbbbbbbbbbb'))
            execute.assert_called_once_with(['ip', '-o', 'netns', 'list'],
                                            run_as_root=False,
                                            log_fail_as_error=True)

    def test_execute(self):
        self.parent.namespace = 'ns'
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            self.netns_cmd.execute(['ip', 'link', 'list'])
            execute.assert_called_once_with(['ip', 'netns', 'exec', 'ns', 'ip',
                                             'link', 'list'],
                                            run_as_root=True,
                                            check_exit_code=True,
                                            extra_ok_codes=None)

    def test_execute_env_var_prepend(self):
        self.parent.namespace = 'ns'
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            env = dict(FOO=1, BAR=2)
            self.netns_cmd.execute(['ip', 'link', 'list'], env)
            execute.assert_called_once_with(
                ['ip', 'netns', 'exec', 'ns', 'env'] +
                ['%s=%s' % (k, v) for k, v in env.items()] +
                ['ip', 'link', 'list'],
                run_as_root=True, check_exit_code=True, extra_ok_codes=None)

    def test_execute_nosudo_with_no_namespace(self):
        with mock.patch('neutron.agent.common.utils.execute') as execute:
            self.parent.namespace = None
            self.netns_cmd.execute(['test'])
            execute.assert_called_once_with(['test'],
                                            check_exit_code=True,
                                            extra_ok_codes=None,
                                            run_as_root=False)


class TestDeviceExists(base.BaseTestCase):
    def test_device_exists(self):
        with mock.patch.object(ip_lib.IPDevice, '_execute') as _execute:
            _execute.return_value = LINK_SAMPLE[1]
            self.assertTrue(ip_lib.device_exists('eth0'))
            _execute.assert_called_once_with(['o'], 'link', ('show', 'eth0'),
                                             log_fail_as_error=False)

    def test_device_does_not_exist(self):
        with mock.patch.object(ip_lib.IPDevice, '_execute') as _execute:
            _execute.return_value = ''
            _execute.side_effect = RuntimeError
            self.assertFalse(ip_lib.device_exists('eth0'))

    def test_ensure_device_is_ready(self):
        ip_lib_mock = mock.Mock()
        with mock.patch.object(ip_lib, 'IPDevice', return_value=ip_lib_mock):
            self.assertTrue(ip_lib.ensure_device_is_ready("eth0"))
            self.assertTrue(ip_lib_mock.link.set_up.called)
            ip_lib_mock.reset_mock()
            # device doesn't exists
            ip_lib_mock.link.set_up.side_effect = RuntimeError
            self.assertFalse(ip_lib.ensure_device_is_ready("eth0"))


class TestIpNeighCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpNeighCommand, self).setUp()
        self.parent.name = 'tap0'
        self.command = 'neigh'
        self.neigh_cmd = ip_lib.IpNeighCommand(self.parent)

    def test_add_entry(self):
        self.neigh_cmd.add('192.168.45.100', 'cc:dd:ee:ff:ab:cd')
        self._assert_sudo([4],
                          ('replace', '192.168.45.100',
                           'lladdr', 'cc:dd:ee:ff:ab:cd',
                           'nud', 'permanent',
                           'dev', 'tap0'))

    def test_delete_entry(self):
        self.neigh_cmd.delete('192.168.45.100', 'cc:dd:ee:ff:ab:cd')
        self._assert_sudo([4],
                          ('del', '192.168.45.100',
                           'lladdr', 'cc:dd:ee:ff:ab:cd',
                           'dev', 'tap0'))

    def test_flush(self):
        self.neigh_cmd.flush(4, '192.168.0.1')
        self._assert_sudo([4], ('flush', 'to', '192.168.0.1'))


class TestArpPing(TestIPCmdBase):
    @mock.patch.object(ip_lib, 'IPWrapper')
    @mock.patch('eventlet.spawn_n')
    def test_send_ipv4_addr_adv_notif(self, spawn_n, mIPWrapper):
        spawn_n.side_effect = lambda f: f()
        ARPING_COUNT = 3
        address = '20.0.0.1'
        config = mock.Mock()
        config.send_arp_for_ha = ARPING_COUNT
        ip_lib.send_ip_addr_adv_notif(mock.sentinel.ns_name,
                                      mock.sentinel.iface_name,
                                      address,
                                      config)

        self.assertTrue(spawn_n.called)
        mIPWrapper.assert_called_once_with(namespace=mock.sentinel.ns_name)

        ip_wrapper = mIPWrapper(namespace=mock.sentinel.ns_name)

        # Just test that arping is called with the right arguments
        arping_cmd = ['arping', '-A',
                      '-I', mock.sentinel.iface_name,
                      '-c', ARPING_COUNT,
                      '-w', mock.ANY,
                      address]
        ip_wrapper.netns.execute.assert_any_call(arping_cmd,
                                                 check_exit_code=True)

    @mock.patch('eventlet.spawn_n')
    def test_no_ipv6_addr_notif(self, spawn_n):
        ipv6_addr = 'fd00::1'
        config = mock.Mock()
        config.send_arp_for_ha = 3
        ip_lib.send_ip_addr_adv_notif(mock.sentinel.ns_name,
                                      mock.sentinel.iface_name,
                                      ipv6_addr,
                                      config)
        self.assertFalse(spawn_n.called)


class TestAddNamespaceToCmd(base.BaseTestCase):
    def test_add_namespace_to_cmd_with_namespace(self):
        cmd = ['ping', '8.8.8.8']
        self.assertEqual(['ip', 'netns', 'exec', 'tmp'] + cmd,
                         ip_lib.add_namespace_to_cmd(cmd, 'tmp'))

    def test_add_namespace_to_cmd_without_namespace(self):
        cmd = ['ping', '8.8.8.8']
        self.assertEqual(cmd, ip_lib.add_namespace_to_cmd(cmd, None))
