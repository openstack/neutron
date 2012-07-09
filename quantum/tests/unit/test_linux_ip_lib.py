# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import unittest

import mock

from quantum.agent.linux import ip_lib
from quantum.agent.linux import utils


LINK_SAMPLE = [
    '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN \\'
    'link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00',
    '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP '
    'qlen 1000\    link/ether cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff',
    '3: br-int: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN '
    '\    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff',
    '4: gw-ddc717df-49: <BROADCAST,MULTICAST> mtu 1500 qdisc noop '
    'state DOWN \    link/ether fe:dc:ba:fe:dc:ba brd ff:ff:ff:ff:ff:ff']

ADDR_SAMPLE = ("""
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP qlen 1000
    link/ether dd:cc:aa:b9:76:ce brd ff:ff:ff:ff:ff:ff
    inet 172.16.77.240/24 brd 172.16.77.255 scope global eth0
    inet6 2001:470:9:1224:5595:dd51:6ba2:e788/64 scope global temporary dynamic
       valid_lft 14187sec preferred_lft 3387sec
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


class TestIPDevice(unittest.TestCase):
    def test_execute_wrapper(self):
        with mock.patch('quantum.agent.linux.utils.execute') as execute:
            ip_lib.IPDevice._execute('o', 'link', ('list',), 'sudo')

            execute.assert_called_once_with(['ip', '-o', 'link', 'list'],
                                            root_helper='sudo')

    def test_execute_wrapper_int_options(self):
        with mock.patch('quantum.agent.linux.utils.execute') as execute:
            ip_lib.IPDevice._execute([4], 'link', ('list',))

            execute.assert_called_once_with(['ip', '-4', 'link', 'list'],
                                            root_helper=None)

    def test_execute_wrapper_no_options(self):
        with mock.patch('quantum.agent.linux.utils.execute') as execute:
            ip_lib.IPDevice._execute([], 'link', ('list',))

            execute.assert_called_once_with(['ip', 'link', 'list'],
                                            root_helper=None)

    def test_get_devices(self):
        with mock.patch.object(ip_lib.IPDevice, '_execute') as _execute:
            _execute.return_value = '\n'.join(LINK_SAMPLE)
            retval = ip_lib.IPDevice.get_devices()
            self.assertEquals(retval,
                              [ip_lib.IPDevice('lo'),
                               ip_lib.IPDevice('eth0'),
                               ip_lib.IPDevice('br-int'),
                               ip_lib.IPDevice('gw-ddc717df-49')])

            _execute.assert_called_once_with('o', 'link', ('list',))


class TestIPCommandBase(unittest.TestCase):
    def setUp(self):
        self.ip_dev = mock.Mock()
        self.ip_dev.name = 'eth0'
        self.ip_dev.root_helper = 'sudo'
        self.ip_dev._execute = mock.Mock(return_value='executed')
        self.ip_cmd = ip_lib.IpCommandBase(self.ip_dev)
        self.ip_cmd.COMMAND = 'foo'

    def test_run(self):
        self.assertEqual(self.ip_cmd._run('link', 'show'), 'executed')
        self.ip_dev._execute.assert_called_once_with([], 'foo',
                                                     ('link', 'show'))

    def test_run_with_options(self):
        self.assertEqual(self.ip_cmd._run('link', options='o'), 'executed')
        self.ip_dev._execute.assert_called_once_with('o', 'foo', ('link',))

    def test_as_root(self):
        self.assertEqual(self.ip_cmd._as_root('link'), 'executed')
        self.ip_dev._execute.assert_called_once_with([], 'foo',
                                                     ('link',), 'sudo')

    def test_as_root_with_options(self):
        self.assertEqual(self.ip_cmd._as_root('link', options='o'), 'executed')
        self.ip_dev._execute.assert_called_once_with('o', 'foo',
                                                     ('link',), 'sudo')

    def test_name_property(self):
        self.assertEqual(self.ip_cmd.name, 'eth0')


class TestIPCmdBase(unittest.TestCase):
    def setUp(self):
        self.parent = mock.Mock()
        self.parent.name = 'eth0'
        self.parent.root_helper = 'sudo'

    def _assert_call(self, options, args):
        self.parent.assert_has_calls([
            mock.call._execute(options, self.command, args)])

    def _assert_sudo(self, options, args):
        self.parent.assert_has_calls([
            mock.call._execute(options, self.command, args, 'sudo')])


class TestIpLinkCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpLinkCommand, self).setUp()
        self.command = 'link'
        self.link_cmd = ip_lib.IpLinkCommand(self.parent)

    def test_set_address(self):
        self.link_cmd.set_address('aa:bb:cc:dd:ee:ff')
        self._assert_sudo([], ('set', 'eth0', 'address', 'aa:bb:cc:dd:ee:ff'))

    def test_set_mtu(self):
        self.link_cmd.set_mtu(1500)
        self._assert_sudo([], ('set', 'eth0', 'mtu', 1500))

    def test_set_up(self):
        self.link_cmd.set_up()
        self._assert_sudo([], ('set', 'eth0', 'up'))

    def test_set_down(self):
        self.link_cmd.set_down()
        self._assert_sudo([], ('set', 'eth0', 'down'))

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

    def test_settings_property(self):
        expected = {'mtu': 1500,
                    'qlen': 1000,
                    'state': 'UP',
                    'qdisc': 'mq',
                    'brd': 'ff:ff:ff:ff:ff:ff',
                    'link/ether': 'cc:dd:ee:ff:ab:cd'}
        self.parent._execute = mock.Mock(return_value=LINK_SAMPLE[1])
        self.assertEquals(self.link_cmd.attributes, expected)
        self._assert_call('o', ('show', 'eth0'))


class TestIpTuntapCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpTuntapCommand, self).setUp()
        self.parent.name = 'tap0'
        self.command = 'tuntap'
        self.tuntap_cmd = ip_lib.IpTuntapCommand(self.parent)

    def test_add_tap(self):
        self.tuntap_cmd.add()
        self._assert_sudo([], ('add', 'tap0', 'mode', 'tap'))


class TestIpAddrCommand(TestIPCmdBase):
    def setUp(self):
        super(TestIpAddrCommand, self).setUp()
        self.parent.name = 'tap0'
        self.command = 'addr'
        self.addr_cmd = ip_lib.IpAddrCommand(self.parent)

    def test_add_address(self):
        self.addr_cmd.add(4, '192.168.45.100/24', '192.168.45.255')
        self._assert_sudo([4],
                          ('add', '192.168.45.100/24', 'brd', '192.168.45.255',
                           'scope', 'global', 'dev', 'tap0'))

    def test_add_address_scoped(self):
        self.addr_cmd.add(4, '192.168.45.100/24', '192.168.45.255',
                          scope='link')
        self._assert_sudo([4],
                          ('add', '192.168.45.100/24', 'brd', '192.168.45.255',
                           'scope', 'link', 'dev', 'tap0'))

    def test_del_address(self):
        self.addr_cmd.delete(4, '192.168.45.100/24')
        self._assert_sudo([4],
                          ('del', '192.168.45.100/24', 'dev', 'tap0'))

    def test_flush(self):
        self.addr_cmd.flush()
        self._assert_sudo([], ('flush', 'tap0'))

    def test_list(self):
        expected = [
            dict(ip_version=4, scope='global',
                 dynamic=False, cidr='172.16.77.240/24'),
            dict(ip_version=6, scope='global',
                 dynamic=True, cidr='2001:470:9:1224:5595:dd51:6ba2:e788/64'),
            dict(ip_version=6, scope='global',
                 dynamic=True, cidr='2001:470:9:1224:fd91:272:581e:3a32/64'),
            dict(ip_version=6, scope='global',
                 dynamic=True, cidr='2001:470:9:1224:4508:b885:5fb:740b/64'),
            dict(ip_version=6, scope='global',
                 dynamic=True, cidr='2001:470:9:1224:dfcc:aaff:feb9:76ce/64'),
            dict(ip_version=6, scope='link',
                 dynamic=False, cidr='fe80::dfcc:aaff:feb9:76ce/64')]

        self.parent._execute = mock.Mock(return_value=ADDR_SAMPLE)
        self.assertEquals(self.addr_cmd.list(), expected)
        self._assert_call([], ('show', 'tap0'))

    def test_list_filtered(self):
        expected = [
            dict(ip_version=4, scope='global',
                 dynamic=False, cidr='172.16.77.240/24')]

        output = '\n'.join(ADDR_SAMPLE.split('\n')[0:4])
        self.parent._execute = mock.Mock(return_value=output)
        self.assertEquals(self.addr_cmd.list('global', filters=['permanent']),
                          expected)
        self._assert_call([], ('show', 'tap0', 'permanent', 'scope', 'global'))


class TestDeviceExists(unittest.TestCase):
    def test_device_exists(self):
        with mock.patch.object(ip_lib.IPDevice, '_execute') as _execute:
            _execute.return_value = LINK_SAMPLE[1]
            self.assertTrue(ip_lib.device_exists('eth0'))
            _execute.assert_called_once_with('o', 'link', ('show', 'eth0'))

    def test_device_does_not_exist(self):
        with mock.patch.object(ip_lib.IPDevice, '_execute') as _execute:
            _execute.return_value = ''
            _execute.side_effect = RuntimeError
            self.assertFalse(ip_lib.device_exists('eth0'))
