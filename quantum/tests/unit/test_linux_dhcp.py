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

import os
import tempfile
import unittest2 as unittest

import mock

from quantum.agent.linux import dhcp
from quantum.agent.common import config
from quantum.openstack.common import cfg


class FakeIPAllocation:
    def __init__(self, address):
        self.ip_address = address


class FakePort1:
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    admin_state_up = True
    fixed_ips = [FakeIPAllocation('192.168.0.2')]
    mac_address = '00:00:80:aa:bb:cc'


class FakePort2:
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    admin_state_up = False
    fixed_ips = [FakeIPAllocation('fdca:3ba5:a17a:4ba3::2')]
    mac_address = '00:00:f3:aa:bb:cc'


class FakePort3:
    id = '44444444-4444-4444-4444-444444444444'
    admin_state_up = True
    fixed_ips = [FakeIPAllocation('192.168.0.3'),
                 FakeIPAllocation('fdca:3ba5:a17a:4ba3::3')]
    mac_address = '00:00:0f:aa:bb:cc'


class FakeV4Subnet:
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'


class FakeV6Subnet:
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    ip_version = 6
    cidr = 'fdca:3ba5:a17a:4ba3::/64'
    gateway_ip = 'fdca:3ba5:a17a:4ba3::1'


class FakeV4Network:
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1()]


class FakeV6Network:
    id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    subnets = [FakeV6Subnet()]
    ports = [FakePort2()]


class FakeDualNetwork:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV6Subnet()]
    ports = [FakePort1(), FakePort2(), FakePort3()]


class TestDhcpBase(unittest.TestCase):
    def test_base_abc_error(self):
        self.assertRaises(TypeError, dhcp.DhcpBase, None)

    def test_replace_file(self):
        # make file to replace
        with mock.patch('tempfile.NamedTemporaryFile') as ntf:
            ntf.return_value.name = '/baz'
            with mock.patch('os.chmod') as chmod:
                with mock.patch('os.rename') as rename:
                    dhcp.replace_file('/foo', 'bar')

                    expected = [mock.call('w+', dir='/', delete=False),
                                mock.call().write('bar'),
                                mock.call().close()]

                    ntf.assert_has_calls(expected)
                    chmod.assert_called_once_with('/baz', 0644)
                    rename.assert_called_once_with('/baz', '/foo')

    def test_restart(self):
        class SubClass(dhcp.DhcpBase):
            def __init__(self):
                dhcp.DhcpBase.__init__(self, None, None)
                self.called = []

            def enable(self):
                self.called.append('enable')

            def disable(self):
                self.called.append('disable')

            def reload_allocations(self):
                pass

            @property
            def active(self):
                return True

        c = SubClass()
        c.restart()
        self.assertEquals(c.called, ['disable', 'enable'])


class LocalChild(dhcp.DhcpLocalProcess):
    PORTS = {4: [4], 6: [6]}

    def __init__(self, *args, **kwargs):
        super(LocalChild, self).__init__(*args, **kwargs)
        self.called = []

    def reload_allocations(self):
        self.called.append('reload')

    def spawn_process(self):
        self.called.append('spawn')


class TestBase(unittest.TestCase):
    def setUp(self):
        root = os.path.dirname(os.path.dirname(__file__))
        args = ['--config-file',
                os.path.join(root, 'etc', 'quantum.conf.test')]
        self.conf = config.setup_conf()
        self.conf.register_opts(dhcp.OPTS)
        self.conf(args=args)
        self.conf.set_override('state_path', '')

        self.replace_p = mock.patch('quantum.agent.linux.dhcp.replace_file')
        self.execute_p = mock.patch('quantum.agent.linux.utils.execute')
        self.safe = self.replace_p.start()
        self.execute = self.execute_p.start()

    def tearDown(self):
        self.execute_p.stop()
        self.replace_p.stop()


class TestDhcpLocalProcess(TestBase):
    def test_active(self):
        dummy_cmd_line = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.execute.return_value = (dummy_cmd_line, '')
        with mock.patch.object(LocalChild, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            lp = LocalChild(self.conf, FakeV4Network())
            self.assertTrue(lp.active)
            self.execute.assert_called_once_with(['cat', '/proc/4/cmdline'],
                                                 'sudo')

    def test_active_cmd_mismatch(self):
        dummy_cmd_line = 'bbbbbbbb-bbbb-bbbb-aaaa-aaaaaaaaaaaa'
        self.execute.return_value = (dummy_cmd_line, '')
        with mock.patch.object(LocalChild, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            lp = LocalChild(self.conf, FakeV4Network())
            self.assertFalse(lp.active)
            self.execute.assert_called_once_with(['cat', '/proc/4/cmdline'],
                                                 'sudo')

    def test_get_conf_file_name(self):
        tpl = '/dhcp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/dev'
        with mock.patch('os.path.isdir') as isdir:
            isdir.return_value = False
            with mock.patch('os.makedirs') as makedirs:
                lp = LocalChild(self.conf, FakeV4Network())
                self.assertEqual(lp.get_conf_file_name('dev'), tpl)
                self.assertFalse(makedirs.called)

    def test_get_conf_file_name_ensure_dir(self):
        tpl = '/dhcp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/dev'
        with mock.patch('os.path.isdir') as isdir:
            isdir.return_value = False
            with mock.patch('os.makedirs') as makedirs:
                lp = LocalChild(self.conf, FakeV4Network())
                self.assertEqual(lp.get_conf_file_name('dev', True), tpl)
                self.assertTrue(makedirs.called)

    def test_enable_already_active(self):
        with mock.patch.object(LocalChild, 'active') as patched:
            patched.__get__ = mock.Mock(return_value=True)
            lp = LocalChild(self.conf, FakeV4Network())
            lp.enable()

            self.assertEqual(lp.called, ['reload'])

    def test_enable(self):
        delegate = mock.Mock(return_value='tap0')
        attrs_to_mock = dict(
            [(a, mock.DEFAULT) for a in
            ['active', 'get_conf_file_name']]
        )

        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['get_conf_file_name'].return_value = '/dir'
            lp = LocalChild(self.conf,
                            FakeDualNetwork(),
                            device_delegate=delegate)
            lp.enable()

            delegate.assert_has_calls(
                [mock.call.setup(mock.ANY, reuse_existing=True)])
            self.assertEqual(lp.called, ['spawn'])

    def test_disable_not_active(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in ['active', 'pid']])
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['pid'].__get__ = mock.Mock(return_value=5)
            with mock.patch.object(dhcp.LOG, 'debug') as log:
                lp = LocalChild(self.conf, FakeDualNetwork())
                lp.disable()
                msg = log.call_args[0][0]
                self.assertIn('stale', msg)

    def test_disable_unknown_network(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in ['active', 'pid']])
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['pid'].__get__ = mock.Mock(return_value=None)
            with mock.patch.object(dhcp.LOG, 'debug') as log:
                lp = LocalChild(self.conf, FakeDualNetwork())
                lp.disable()
                msg = log.call_args[0][0]
                self.assertIn('No DHCP', msg)

    def test_disable(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'pid']])
        delegate = mock.Mock()
        delegate.intreface_name = 'tap0'
        network = FakeDualNetwork()
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=True)
            mocks['pid'].__get__ = mock.Mock(return_value=5)
            lp = LocalChild(self.conf, network, device_delegate=delegate)
            lp.disable()

        delegate.assert_has_calls([mock.call.destroy(network)])
        self.execute.assert_called_once_with(['kill', '-9', 5], 'sudo')

    def test_pid(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.read.return_value = '5'
            lp = LocalChild(self.conf, FakeDualNetwork())
            self.assertEqual(lp.pid, 5)

    def test_pid_no_an_int(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.read.return_value = 'foo'
            lp = LocalChild(self.conf, FakeDualNetwork())
            self.assertIsNone(lp.pid)

    def test_pid_invalid_file(self):
        with mock.patch.object(LocalChild, 'get_conf_file_name') as conf_file:
            conf_file.return_value = '.doesnotexist/pid'
            lp = LocalChild(self.conf, FakeDualNetwork())
            self.assertIsNone(lp.pid)


class TestDnsmasq(TestBase):
    def _test_spawn(self, extra_options):
        def mock_get_conf_file_name(kind, ensure_conf_dir=False):
            return '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/%s' % kind

        expected = [
            'NETWORK_ID=cccccccc-cccc-cccc-cccc-cccccccccccc',
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=tap0',
            '--except-interface=lo',
            '--domain=openstacklocal',
            '--pid-file=/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/pid',
            '--dhcp-hostsfile=/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host',
            '--dhcp-optsfile=/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts',
            '--leasefile-ro',
            '--dhcp-range=set:tag0,192.168.0.0,static,120s',
            '--dhcp-range=set:tag1,fdca:3ba5:a17a:4ba3::,static,120s'
        ]
        expected.extend(extra_options)

        self.execute.return_value = ('', '')
        delegate = mock.Mock()
        delegate.get_interface_name.return_value = 'tap0'

        attrs_to_mock = dict(
            [(a, mock.DEFAULT) for a in
            ['_output_opts_file', 'get_conf_file_name']]
        )

        with mock.patch.multiple(dhcp.Dnsmasq, **attrs_to_mock) as mocks:
            mocks['get_conf_file_name'].side_effect = mock_get_conf_file_name
            mocks['_output_opts_file'].return_value = (
                '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts'
            )
            dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork(),
                              device_delegate=delegate)
            dm.spawn_process()
            self.assertTrue(mocks['_output_opts_file'].called)
            self.execute.assert_called_once_with(expected, 'sudo')

    def test_spawn(self):
        self._test_spawn([])

    def test_spawn_cfg_config_file(self):
        self.conf.set_override('dnsmasq_config_file', '/foo')
        self._test_spawn(['--conf-file=/foo'])

    def test_spawn_cfg_dns_server(self):
        self.conf.set_override('dnsmasq_dns_server', '8.8.8.8')
        self._test_spawn(['--server=8.8.8.8'])

    def test_output_opts_file(self):
        expected = 'tag:tag0,option:router,192.168.0.1'
        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork())
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_reload_allocations(self):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = """
00:00:80:aa:bb:cc,192-168-0-2.openstacklocal,192.168.0.2
00:00:f3:aa:bb:cc,fdca-3ba5-a17a-4ba3--2.openstacklocal,fdca:3ba5:a17a:4ba3::2
00:00:0f:aa:bb:cc,192-168-0-3.openstacklocal,192.168.0.3
00:00:0f:aa:bb:cc,fdca-3ba5-a17a-4ba3--3.openstacklocal,fdca:3ba5:a17a:4ba3::3
""".lstrip()
        exp_opt_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts'
        exp_opt_data = "tag:tag0,option:router,192.168.0.1"

        with mock.patch('os.path.isdir') as isdir:
            isdir.return_value = True
            with mock.patch.object(dhcp.Dnsmasq, 'pid') as pid:
                pid.__get__ = mock.Mock(return_value=5)
                dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork())
                dm.reload_allocations()

        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])
        self.execute.assert_called_once_with(['kill', '-HUP', 5], 'sudo')
