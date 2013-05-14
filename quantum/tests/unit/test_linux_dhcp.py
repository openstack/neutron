# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import os
import socket

import mock
from oslo.config import cfg

from quantum.agent.common import config
from quantum.agent.linux import dhcp
from quantum.openstack.common import jsonutils
from quantum.tests import base


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


class FakeV4HostRoute:
    destination = '20.0.0.1/24'
    nexthop = '20.0.0.1'


class FakeV6HostRoute:
    destination = 'gdca:3ba5:a17a:4ba3::/64'
    nexthop = 'gdca:3ba5:a17a:4ba3::1'


class FakeV4Subnet:
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True
    host_routes = [FakeV4HostRoute]
    dns_nameservers = ['8.8.8.8']


class FakeV6Subnet:
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    ip_version = 6
    cidr = 'fdca:3ba5:a17a:4ba3::/64'
    gateway_ip = 'fdca:3ba5:a17a:4ba3::1'
    enable_dhcp = True
    host_routes = [FakeV6HostRoute]
    dns_nameservers = ['gdca:3ba5:a17a:4ba3::1']


class FakeV4SubnetNoDHCP:
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = '192.168.1.1'
    enable_dhcp = False
    host_routes = []
    dns_nameservers = []


class FakeV4SubnetNoGateway:
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = None
    enable_dhcp = True
    host_routes = []
    dns_nameservers = []


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


class FakeDualNetworkSingleDHCP:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV4SubnetNoDHCP()]
    ports = [FakePort1(), FakePort2(), FakePort3()]


class FakeV4NoGatewayNetwork:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetNoGateway()]
    ports = [FakePort1()]


class TestDhcpBase(base.BaseTestCase):
    def test_existing_dhcp_networks_abstract_error(self):
        self.assertRaises(NotImplementedError,
                          dhcp.DhcpBase.existing_dhcp_networks,
                          None, None)

    def test_check_version_abstract_error(self):
        self.assertRaises(NotImplementedError,
                          dhcp.DhcpBase.check_version)

    def test_base_abc_error(self):
        self.assertRaises(TypeError, dhcp.DhcpBase, None)

    def test_restart(self):
        class SubClass(dhcp.DhcpBase):
            def __init__(self):
                dhcp.DhcpBase.__init__(self, None, None, None)
                self.called = []

            def enable(self):
                self.called.append('enable')

            def disable(self, retain_port=False):
                self.called.append('disable %s' % retain_port)

            def reload_allocations(self):
                pass

            @property
            def active(self):
                return True

        c = SubClass()
        c.restart()
        self.assertEqual(c.called, ['disable True', 'enable'])


class LocalChild(dhcp.DhcpLocalProcess):
    PORTS = {4: [4], 6: [6]}

    def __init__(self, *args, **kwargs):
        super(LocalChild, self).__init__(*args, **kwargs)
        self.called = []

    def reload_allocations(self):
        self.called.append('reload')

    def restart(self):
        self.called.append('restart')

    def spawn_process(self):
        self.called.append('spawn')


class TestBase(base.BaseTestCase):
    def setUp(self):
        super(TestBase, self).setUp()
        root = os.path.dirname(os.path.dirname(__file__))
        args = ['--config-file',
                os.path.join(root, 'etc', 'quantum.conf.test')]
        self.conf = config.setup_conf()
        self.conf.register_opts(dhcp.OPTS)
        self.conf.register_opt(
            cfg.StrOpt('dhcp_lease_relay_socket',
                       default='$state_path/dhcp/lease_relay'))
        self.conf.register_opt(cfg.BoolOpt('enable_isolated_metadata',
                                           default=True))
        self.conf(args=args)
        self.conf.set_override('state_path', '')
        self.conf.use_namespaces = True

        self.replace_p = mock.patch('quantum.agent.linux.utils.replace_file')
        self.execute_p = mock.patch('quantum.agent.linux.utils.execute')
        self.addCleanup(self.execute_p.stop)
        self.safe = self.replace_p.start()
        self.addCleanup(self.replace_p.stop)
        self.execute = self.execute_p.start()


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

    def test_active_none(self):
        dummy_cmd_line = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.execute.return_value = (dummy_cmd_line, '')
        with mock.patch.object(LocalChild, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=None)
            lp = LocalChild(self.conf, FakeV4Network())
            self.assertFalse(lp.active)

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
        delegate = mock.Mock()
        delegate.setup.return_value = 'tap0'
        with mock.patch.object(LocalChild, 'active') as patched:
            patched.__get__ = mock.Mock(return_value=True)
            lp = LocalChild(self.conf, FakeV4Network(),
                            device_delegate=delegate)
            lp.enable()

            self.assertEqual(lp.called, ['restart'])

    def test_enable(self):
        delegate = mock.Mock(return_value='tap0')
        attrs_to_mock = dict(
            [(a, mock.DEFAULT) for a in
            ['active', 'get_conf_file_name', 'interface_name']]
        )

        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['get_conf_file_name'].return_value = '/dir'
            mocks['interface_name'].__set__ = mock.Mock()
            lp = LocalChild(self.conf,
                            FakeDualNetwork(),
                            device_delegate=delegate)
            lp.enable()

            delegate.assert_has_calls(
                [mock.call.setup(mock.ANY, reuse_existing=True)])
            self.assertEqual(lp.called, ['spawn'])
            self.assertTrue(mocks['interface_name'].__set__.called)

    def test_disable_not_active(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'interface_name', 'pid']])
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['pid'].__get__ = mock.Mock(return_value=5)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            with mock.patch.object(dhcp.LOG, 'debug') as log:
                lp = LocalChild(self.conf, FakeDualNetwork())
                lp.disable()
                msg = log.call_args[0][0]
                self.assertIn('stale', msg)

    def test_disable_unknown_network(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'interface_name', 'pid']])
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['pid'].__get__ = mock.Mock(return_value=None)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            with mock.patch.object(dhcp.LOG, 'debug') as log:
                lp = LocalChild(self.conf, FakeDualNetwork())
                lp.disable()
                msg = log.call_args[0][0]
                self.assertIn('No DHCP', msg)

    def test_disable_retain_port(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'interface_name', 'pid']])
        delegate = mock.Mock()
        network = FakeDualNetwork()
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=True)
            mocks['pid'].__get__ = mock.Mock(return_value=5)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            lp = LocalChild(self.conf, network, device_delegate=delegate,
                            namespace='qdhcp-ns')
            lp.disable(retain_port=True)

        self.assertFalse(delegate.called)
        exp_args = ['ip', 'netns', 'exec', 'qdhcp-ns', 'kill', '-9', 5]
        self.execute.assert_called_once_with(exp_args, root_helper='sudo',
                                             check_exit_code=True)

    def test_disable(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'interface_name', 'pid']])
        delegate = mock.Mock()
        network = FakeDualNetwork()
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=True)
            mocks['pid'].__get__ = mock.Mock(return_value=5)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            lp = LocalChild(self.conf, network, device_delegate=delegate,
                            namespace='qdhcp-ns')
            lp.disable()

        delegate.assert_has_calls([mock.call.destroy(network, 'tap0')])
        exp_args = ['ip', 'netns', 'exec', 'qdhcp-ns', 'kill', '-9', 5]
        self.execute.assert_called_once_with(exp_args, root_helper='sudo',
                                             check_exit_code=True)

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

    def test_get_interface_name(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.read.return_value = 'tap0'
            lp = LocalChild(self.conf, FakeDualNetwork())
            self.assertEqual(lp.interface_name, 'tap0')

    def test_set_interface_name(self):
        with mock.patch('quantum.agent.linux.utils.replace_file') as replace:
            lp = LocalChild(self.conf, FakeDualNetwork())
            with mock.patch.object(lp, 'get_conf_file_name') as conf_file:
                conf_file.return_value = '/interface'
                lp.interface_name = 'tap0'
                conf_file.assert_called_once_with('interface',
                                                  ensure_conf_dir=True)
                replace.assert_called_once_with(mock.ANY, 'tap0')


class TestDnsmasq(TestBase):
    def _test_spawn(self, extra_options):
        def mock_get_conf_file_name(kind, ensure_conf_dir=False):
            return '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/%s' % kind

        def fake_argv(index):
            if index == 0:
                return '/usr/local/bin/quantum-dhcp-agent'
            else:
                raise IndexError

        expected = [
            'QUANTUM_RELAY_SOCKET_PATH=/dhcp/lease_relay',
            'QUANTUM_NETWORK_ID=cccccccc-cccc-cccc-cccc-cccccccccccc',
            'ip',
            'netns',
            'exec',
            'qdhcp-ns',
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=tap0',
            '--except-interface=lo',
            '--pid-file=/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/pid',
            '--dhcp-hostsfile=/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host',
            '--dhcp-optsfile=/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts',
            ('--dhcp-script=/usr/local/bin/quantum-dhcp-agent-'
             'dnsmasq-lease-update'),
            '--leasefile-ro',
            '--dhcp-range=set:tag0,192.168.0.0,static,120s',
            '--dhcp-range=set:tag1,fdca:3ba5:a17a:4ba3::,static,120s']
        expected.extend(extra_options)

        self.execute.return_value = ('', '')
        delegate = mock.Mock()
        delegate.get_interface_name.return_value = 'tap0'

        attrs_to_mock = dict(
            [(a, mock.DEFAULT) for a in
            ['_output_opts_file', 'get_conf_file_name', 'interface_name']]
        )

        with mock.patch.multiple(dhcp.Dnsmasq, **attrs_to_mock) as mocks:
            mocks['get_conf_file_name'].side_effect = mock_get_conf_file_name
            mocks['_output_opts_file'].return_value = (
                '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts'
            )
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')

            with mock.patch.object(dhcp.sys, 'argv') as argv:
                argv.__getitem__.side_effect = fake_argv
                dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork(),
                                  device_delegate=delegate,
                                  namespace='qdhcp-ns',
                                  version=float(2.59))
                dm.spawn_process()
                self.assertTrue(mocks['_output_opts_file'].called)
                self.execute.assert_called_once_with(expected,
                                                     root_helper='sudo',
                                                     check_exit_code=True)

    def test_spawn(self):
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'])

    def test_spawn_cfg_config_file(self):
        self.conf.set_override('dnsmasq_config_file', '/foo')
        self._test_spawn(['--conf-file=/foo', '--domain=openstacklocal'])

    def test_spawn_no_dhcp_domain(self):
        self.conf.set_override('dhcp_domain', '')
        self._test_spawn(['--conf-file='])

    def test_spawn_cfg_dns_server(self):
        self.conf.set_override('dnsmasq_dns_server', '8.8.8.8')
        self._test_spawn(['--conf-file=',
                          '--server=8.8.8.8',
                          '--domain=openstacklocal'])

    def test_output_opts_file(self):
        fake_v6 = 'gdca:3ba5:a17a:4ba3::1'
        fake_v6_cidr = 'gdca:3ba5:a17a:4ba3::/64'
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:tag1,option:dns-server,%s
tag:tag1,option:classless-static-route,%s,%s""".lstrip() % (fake_v6,
                                                            fake_v6_cidr,
                                                            fake_v6)

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork(),
                              version=float(2.59))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_single_dhcp(self):
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1""".lstrip()
        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeDualNetworkSingleDHCP(),
                              version=float(2.59))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_single_dhcp_ver2_48(self):
        expected = """
tag0,option:dns-server,8.8.8.8
tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag0,option:router,192.168.0.1""".lstrip()
        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeDualNetworkSingleDHCP(),
                              version=float(2.48))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_no_gateway(self):
        expected = """
tag:tag0,option:classless-static-route,169.254.169.254/32,192.168.1.1
tag:tag0,option:router""".lstrip()

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeV4NoGatewayNetwork(),
                              version=float(2.59))
            with mock.patch.object(dm, '_make_subnet_interface_ip_map') as ipm:
                ipm.return_value = {FakeV4SubnetNoGateway.id: '192.168.1.1'}

                dm._output_opts_file()
                self.assertTrue(ipm.called)

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
        fake_v6 = 'gdca:3ba5:a17a:4ba3::1'
        fake_v6_cidr = 'gdca:3ba5:a17a:4ba3::/64'
        exp_opt_data = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:tag1,option:dns-server,%s
tag:tag1,option:classless-static-route,%s,%s""".lstrip() % (fake_v6,
                                                            fake_v6_cidr,
                                                            fake_v6)

        exp_args = ['ip', 'netns', 'exec', 'qdhcp-ns', 'kill', '-HUP', 5]

        with mock.patch('os.path.isdir') as isdir:
            isdir.return_value = True
            with mock.patch.object(dhcp.Dnsmasq, 'active') as active:
                active.__get__ = mock.Mock(return_value=True)
                with mock.patch.object(dhcp.Dnsmasq, 'pid') as pid:
                    pid.__get__ = mock.Mock(return_value=5)
                    dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork(),
                                      namespace='qdhcp-ns',
                                      version=float(2.59))

                    method_name = '_make_subnet_interface_ip_map'
                    with mock.patch.object(dhcp.Dnsmasq,
                                           method_name) as ip_map:
                        ip_map.return_value = {}
                        dm.reload_allocations()
                        self.assertTrue(ip_map.called)

        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])
        self.execute.assert_called_once_with(exp_args, root_helper='sudo',
                                             check_exit_code=True)

    def test_reload_allocations_stale_pid(self):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = """
00:00:80:aa:bb:cc,192-168-0-2.openstacklocal,192.168.0.2
00:00:f3:aa:bb:cc,fdca-3ba5-a17a-4ba3--2.openstacklocal,fdca:3ba5:a17a:4ba3::2
00:00:0f:aa:bb:cc,192-168-0-3.openstacklocal,192.168.0.3
00:00:0f:aa:bb:cc,fdca-3ba5-a17a-4ba3--3.openstacklocal,fdca:3ba5:a17a:4ba3::3
""".lstrip()
        exp_opt_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts'
        exp_opt_data = "tag:tag0,option:router,192.168.0.1"
        fake_v6 = 'gdca:3ba5:a17a:4ba3::1'
        fake_v6_cidr = 'gdca:3ba5:a17a:4ba3::/64'
        exp_opt_data = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:tag1,option:dns-server,%s
tag:tag1,option:classless-static-route,%s,%s""".lstrip() % (fake_v6,
                                                            fake_v6_cidr,
                                                            fake_v6)

        exp_args = ['cat', '/proc/5/cmdline']

        with mock.patch('os.path.isdir') as isdir:
            isdir.return_value = True
            with mock.patch.object(dhcp.Dnsmasq, 'pid') as pid:
                pid.__get__ = mock.Mock(return_value=5)
                dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork(),
                                  namespace='qdhcp-ns', version=float(2.59))

                method_name = '_make_subnet_interface_ip_map'
                with mock.patch.object(dhcp.Dnsmasq, method_name) as ip_map:
                    ip_map.return_value = {}
                    dm.reload_allocations()
                    self.assertTrue(ip_map.called)

        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])
        self.execute.assert_called_once_with(exp_args, 'sudo')

    def test_make_subnet_interface_ip_map(self):
        with mock.patch('quantum.agent.linux.ip_lib.IPDevice') as ip_dev:
            ip_dev.return_value.addr.list.return_value = [
                {'cidr': '192.168.0.1/24'}
            ]

            dm = dhcp.Dnsmasq(self.conf,
                              FakeDualNetwork(),
                              namespace='qdhcp-ns')

            self.assertEqual(
                dm._make_subnet_interface_ip_map(),
                {FakeV4Subnet.id: '192.168.0.1'}
            )

    def _test_lease_relay_script_helper(self, action, lease_remaining,
                                        path_exists=True):
        relay_path = '/dhcp/relay_socket'
        network_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        mac_address = 'aa:bb:cc:dd:ee:ff'
        ip_address = '192.168.1.9'

        json_rep = jsonutils.dumps(dict(network_id=network_id,
                                        lease_remaining=lease_remaining,
                                        mac_address=mac_address,
                                        ip_address=ip_address))

        environ = {
            'QUANTUM_NETWORK_ID': network_id,
            'QUANTUM_RELAY_SOCKET_PATH': relay_path,
            'DNSMASQ_TIME_REMAINING': '120',
        }

        def fake_environ(name, default=None):
            return environ.get(name, default)

        with mock.patch('os.environ') as mock_environ:
            mock_environ.get.side_effect = fake_environ

            with mock.patch.object(dhcp, 'sys') as mock_sys:
                mock_sys.argv = [
                    'lease-update',
                    action,
                    mac_address,
                    ip_address,
                ]

                with mock.patch('socket.socket') as mock_socket:
                    mock_conn = mock.Mock()
                    mock_socket.return_value = mock_conn

                    with mock.patch('os.path.exists') as mock_exists:
                        mock_exists.return_value = path_exists

                        dhcp.Dnsmasq.lease_update()

                        mock_exists.assert_called_once_with(relay_path)
                        if path_exists:
                            mock_socket.assert_called_once_with(
                                socket.AF_UNIX, socket.SOCK_STREAM)

                            mock_conn.assert_has_calls(
                                [mock.call.connect(relay_path),
                                 mock.call.send(json_rep),
                                 mock.call.close()])

    def test_lease_relay_script_add(self):
        self._test_lease_relay_script_helper('add', 120)

    def test_lease_relay_script_old(self):
        self._test_lease_relay_script_helper('old', 120)

    def test_lease_relay_script_del(self):
        self._test_lease_relay_script_helper('del', 0)

    def test_lease_relay_script_add_socket_missing(self):
        self._test_lease_relay_script_helper('add', 120, False)

    def test_remove_config_files(self):
        net = FakeV4Network()
        path = '/opt/data/quantum/dhcp'
        self.conf.dhcp_confs = path

        with mock.patch('shutil.rmtree') as rmtree:
            lp = LocalChild(self.conf, net)
            lp._remove_config_files()

            rmtree.assert_called_once_with(os.path.join(path, net.id),
                                           ignore_errors=True)

    def test_existing_dhcp_networks(self):
        path = '/opt/data/quantum/dhcp'
        self.conf.dhcp_confs = path

        cases = {
            # network_uuid --> is_dhcp_alive?
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa': True,
            'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb': False,
            'not_uuid_like_name': True
        }

        def active_fake(self, instance, cls):
            return cases[instance.network.id]

        with mock.patch('os.listdir') as mock_listdir:
            with mock.patch.object(dhcp.Dnsmasq, 'active') as mock_active:
                mock_active.__get__ = active_fake
                mock_listdir.return_value = cases.keys()

                result = dhcp.Dnsmasq.existing_dhcp_networks(self.conf, 'sudo')

                mock_listdir.assert_called_once_with(path)
                self.assertEquals(['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'],
                                  result)

    def _check_version(self, cmd_out, expected_value):
        with mock.patch('quantum.agent.linux.utils.execute') as cmd:
            cmd.return_value = cmd_out
            result = dhcp.Dnsmasq.check_version()
            self.assertEqual(result, expected_value)

    def test_check_minimum_version(self):
        self._check_version('Dnsmasq version 2.59 Copyright (c)...',
                            float(2.59))

    def test_check_future_version(self):
        self._check_version('Dnsmasq version 2.65 Copyright (c)...',
                            float(2.65))

    def test_check_fail_version(self):
        self._check_version('Dnsmasq version 2.48 Copyright (c)...',
                            float(2.48))

    def test_check_version_failed_cmd_execution(self):
        self._check_version('Error while executing command', 0)
