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

import contextlib
import os

import mock
from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import dhcp
from neutron.common import config as base_config
from neutron.common import constants
from neutron.openstack.common import log as logging
from neutron.tests import base

LOG = logging.getLogger(__name__)


class FakeIPAllocation:
    def __init__(self, address, subnet_id=None):
        self.ip_address = address
        self.subnet_id = subnet_id


class DhcpOpt(object):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __str__(self):
        return str(self.__dict__)


class FakePort1:
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    admin_state_up = True
    device_owner = 'foo1'
    fixed_ips = [FakeIPAllocation('192.168.0.2')]
    mac_address = '00:00:80:aa:bb:cc'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePort2:
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    admin_state_up = False
    device_owner = 'foo2'
    fixed_ips = [FakeIPAllocation('fdca:3ba5:a17a:4ba3::2')]
    mac_address = '00:00:f3:aa:bb:cc'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePort3:
    id = '44444444-4444-4444-4444-444444444444'
    admin_state_up = True
    device_owner = 'foo3'
    fixed_ips = [FakeIPAllocation('192.168.0.3'),
                 FakeIPAllocation('fdca:3ba5:a17a:4ba3::3')]
    mac_address = '00:00:0f:aa:bb:cc'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakeRouterPort:
    id = 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr'
    admin_state_up = True
    device_owner = constants.DEVICE_OWNER_ROUTER_INTF
    fixed_ips = [FakeIPAllocation('192.168.0.1',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:0f:rr:rr:rr'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePortMultipleAgents1:
    id = 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr'
    admin_state_up = True
    device_owner = constants.DEVICE_OWNER_DHCP
    fixed_ips = [FakeIPAllocation('192.168.0.5',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:0f:dd:dd:dd'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePortMultipleAgents2:
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    admin_state_up = True
    device_owner = constants.DEVICE_OWNER_DHCP
    fixed_ips = [FakeIPAllocation('192.168.0.6',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:0f:ee:ee:ee'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakeV4HostRoute:
    destination = '20.0.0.1/24'
    nexthop = '20.0.0.1'


class FakeV4HostRouteGateway:
    destination = '0.0.0.0/0'
    nexthop = '10.0.0.1'


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


class FakeV4SubnetGatewayRoute:
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True
    host_routes = [FakeV4HostRouteGateway]
    dns_nameservers = ['8.8.8.8']


class FakeV4SubnetMultipleAgentsWithoutDnsProvided:
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True
    dns_nameservers = []
    host_routes = []


class FakeV4MultipleAgentsWithoutDnsProvided:
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    subnets = [FakeV4SubnetMultipleAgentsWithoutDnsProvided()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
             FakePortMultipleAgents1(), FakePortMultipleAgents2()]
    namespace = 'qdhcp-ns'


class FakeV4SubnetMultipleAgentsWithDnsProvided:
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True
    dns_nameservers = ['8.8.8.8']
    host_routes = []


class FakeV4MultipleAgentsWithDnsProvided:
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    subnets = [FakeV4SubnetMultipleAgentsWithDnsProvided()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
             FakePortMultipleAgents1(), FakePortMultipleAgents2()]
    namespace = 'qdhcp-ns'


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


class FakeV4SubnetNoRouter:
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = '192.168.1.1'
    enable_dhcp = True
    host_routes = []
    dns_nameservers = []


class FakeV4Network:
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1()]
    namespace = 'qdhcp-ns'


class FakeV6Network:
    id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    subnets = [FakeV6Subnet()]
    ports = [FakePort2()]
    namespace = 'qdhcp-ns'


class FakeDualNetwork:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV6Subnet()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'


class FakeDualNetworkGatewayRoute:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetGatewayRoute(), FakeV6Subnet()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'


class FakeDualNetworkSingleDHCP:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV4SubnetNoDHCP()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'


class FakeV4NoGatewayNetwork:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetNoGateway()]
    ports = [FakePort1()]


class FakeV4NetworkNoRouter:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetNoRouter()]
    ports = [FakePort1()]


class FakeDualV4Pxe3Ports:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV4SubnetNoDHCP()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'

    def __init__(self, port_detail="portsSame"):
        if port_detail == "portsSame":
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.1.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.1.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux2.0')]
            self.ports[2].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.1.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.1.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux3.0')]
        else:
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux2.0')]
            self.ports[2].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.7'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.7'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux3.0')]


class FakeV4NetworkPxe2Ports:
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1(), FakePort2(), FakeRouterPort()]
    namespace = 'qdhcp-ns'

    def __init__(self, port_detail="portsSame"):
        if port_detail == "portsSame":
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
        else:
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]


class FakeV4NetworkPxe3Ports:
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'

    def __init__(self, port_detail="portsSame"):
        if port_detail == "portsSame":
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.1.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.1.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[2].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.1.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.1.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
        else:
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux2.0')]
            self.ports[2].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.7'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.7'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux3.0')]


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
                os.path.join(root, 'etc', 'neutron.conf.test')]
        self.conf = config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(dhcp.OPTS)
        config.register_interface_driver_opts_helper(self.conf)
        instance = mock.patch("neutron.agent.linux.dhcp.DeviceManager")
        self.mock_mgr = instance.start()
        self.conf.register_opt(cfg.BoolOpt('enable_isolated_metadata',
                                           default=True))
        self.conf(args=args)
        self.conf.set_override('state_path', '')
        self.conf.use_namespaces = True

        self.replace_p = mock.patch('neutron.agent.linux.utils.replace_file')
        self.execute_p = mock.patch('neutron.agent.linux.utils.execute')
        self.safe = self.replace_p.start()
        self.execute = self.execute_p.start()


class TestDhcpBase(TestBase):

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
                dhcp.DhcpBase.__init__(self, cfg.CONF, FakeV4Network(), None)
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


class TestDhcpLocalProcess(TestBase):
    def test_active(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.readline.return_value = \
                'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

            with mock.patch.object(LocalChild, 'pid') as pid:
                pid.__get__ = mock.Mock(return_value=4)
                lp = LocalChild(self.conf, FakeV4Network())
                self.assertTrue(lp.active)

            mock_open.assert_called_once_with('/proc/4/cmdline', 'r')

    def test_active_none(self):
        dummy_cmd_line = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.execute.return_value = (dummy_cmd_line, '')
        with mock.patch.object(LocalChild, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=None)
            lp = LocalChild(self.conf, FakeV4Network())
            self.assertFalse(lp.active)

    def test_active_cmd_mismatch(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.readline.return_value = \
                'bbbbbbbb-bbbb-bbbb-aaaa-aaaaaaaaaaaa'

            with mock.patch.object(LocalChild, 'pid') as pid:
                pid.__get__ = mock.Mock(return_value=4)
                lp = LocalChild(self.conf, FakeV4Network())
                self.assertFalse(lp.active)

            mock_open.assert_called_once_with('/proc/4/cmdline', 'r')

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

            self.assertEqual(lp.called, ['restart'])

    def test_enable(self):
        attrs_to_mock = dict(
            [(a, mock.DEFAULT) for a in
                ['active', 'get_conf_file_name', 'interface_name']]
        )

        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['get_conf_file_name'].return_value = '/dir'
            mocks['interface_name'].__set__ = mock.Mock()
            lp = LocalChild(self.conf,
                            FakeDualNetwork())
            lp.enable()

            self.mock_mgr.assert_has_calls(
                [mock.call(self.conf, 'sudo', None),
                 mock.call().setup(mock.ANY, reuse_existing=True)])
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
        network = FakeDualNetwork()
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=True)
            mocks['pid'].__get__ = mock.Mock(return_value=5)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            lp = LocalChild(self.conf, network)
            lp.disable(retain_port=True)

            exp_args = ['kill', '-9', 5]
            self.execute.assert_called_once_with(exp_args, 'sudo')

    def test_disable(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'interface_name', 'pid']])
        network = FakeDualNetwork()
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=True)
            mocks['pid'].__get__ = mock.Mock(return_value=5)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            lp = LocalChild(self.conf, network)
            with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip:
                lp.disable()

        self.mock_mgr.assert_has_calls([mock.call(self.conf, 'sudo', None),
                                        mock.call().destroy(network, 'tap0')])
        exp_args = ['kill', '-9', 5]
        self.execute.assert_called_once_with(exp_args, 'sudo')

        self.assertEqual(ip.return_value.netns.delete.call_count, 0)

    def test_disable_delete_ns(self):
        self.conf.set_override('dhcp_delete_namespaces', True)
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in ['active', 'pid']])

        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['pid'].__get__ = mock.Mock(return_value=False)
            lp = LocalChild(self.conf, FakeDualNetwork())
            with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip:
                lp.disable()

        ip.return_value.netns.delete.assert_called_with('qdhcp-ns')

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
        with mock.patch('neutron.agent.linux.utils.replace_file') as replace:
            lp = LocalChild(self.conf, FakeDualNetwork())
            with mock.patch.object(lp, 'get_conf_file_name') as conf_file:
                conf_file.return_value = '/interface'
                lp.interface_name = 'tap0'
                conf_file.assert_called_once_with('interface',
                                                  ensure_conf_dir=True)
                replace.assert_called_once_with(mock.ANY, 'tap0')


class TestDnsmasq(TestBase):
    def _test_spawn(self, extra_options, network=FakeDualNetwork(),
                    max_leases=16777216):
        def mock_get_conf_file_name(kind, ensure_conf_dir=False):
            return '/dhcp/%s/%s' % (network.id, kind)

        def fake_argv(index):
            if index == 0:
                return '/usr/local/bin/neutron-dhcp-agent'
            else:
                raise IndexError

        expected = [
            'ip',
            'netns',
            'exec',
            'qdhcp-ns',
            'env',
            'NEUTRON_NETWORK_ID=%s' % network.id,
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=tap0',
            '--except-interface=lo',
            '--pid-file=/dhcp/%s/pid' % network.id,
            '--dhcp-hostsfile=/dhcp/%s/host' % network.id,
            '--addn-hosts=/dhcp/%s/addn_hosts' % network.id,
            '--dhcp-optsfile=/dhcp/%s/opts' % network.id,
            '--leasefile-ro']

        expected.extend(
            '--dhcp-range=set:tag%d,%s,static,86400s' %
            (i, s.cidr.split('/')[0])
            for i, s in enumerate(network.subnets)
        )
        expected.append('--dhcp-lease-max=%d' % max_leases)
        expected.extend(extra_options)

        self.execute.return_value = ('', '')

        attrs_to_mock = dict(
            [(a, mock.DEFAULT) for a in
                ['_output_opts_file', 'get_conf_file_name', 'interface_name']]
        )

        with mock.patch.multiple(dhcp.Dnsmasq, **attrs_to_mock) as mocks:
            mocks['get_conf_file_name'].side_effect = mock_get_conf_file_name
            mocks['_output_opts_file'].return_value = (
                '/dhcp/%s/opts' % network.id
            )
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')

            with mock.patch.object(dhcp.sys, 'argv') as argv:
                argv.__getitem__.side_effect = fake_argv
                dm = dhcp.Dnsmasq(self.conf, network, version=float(2.59))
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
        self.conf.set_override('dnsmasq_dns_servers', ['8.8.8.8'])
        self._test_spawn(['--conf-file=',
                          '--server=8.8.8.8',
                          '--domain=openstacklocal'])

    def test_spawn_cfg_multiple_dns_server(self):
        self.conf.set_override('dnsmasq_dns_servers', ['8.8.8.8',
                                                       '9.9.9.9'])
        self._test_spawn(['--conf-file=',
                          '--server=8.8.8.8',
                          '--server=9.9.9.9',
                          '--domain=openstacklocal'])

    def test_spawn_max_leases_is_smaller_than_cap(self):
        self._test_spawn(
            ['--conf-file=', '--domain=openstacklocal'],
            network=FakeV4Network(),
            max_leases=256)

    def test_output_opts_file(self):
        fake_v6 = 'gdca:3ba5:a17a:4ba3::1'
        fake_v6_cidr = 'gdca:3ba5:a17a:4ba3::/64'
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,249,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:tag1,option:dns-server,%s
tag:tag1,option:classless-static-route,%s,%s
tag:tag1,249,%s,%s""".lstrip() % (fake_v6,
                                  fake_v6_cidr, fake_v6,
                                  fake_v6_cidr, fake_v6)

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork(),
                              version=float(2.59))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_gateway_route(self):
        fake_v6 = 'gdca:3ba5:a17a:4ba3::1'
        fake_v6_cidr = 'gdca:3ba5:a17a:4ba3::/64'
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:router,10.0.0.1
tag:tag1,option:dns-server,%s
tag:tag1,option:classless-static-route,%s,%s
tag:tag1,249,%s,%s""".lstrip() % (fake_v6,
                                  fake_v6_cidr, fake_v6,
                                  fake_v6_cidr, fake_v6)

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeDualNetworkGatewayRoute(),
                              version=float(2.59))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_multiple_agents_without_dns_provided(self):
        expected = """
tag:tag0,option:router,192.168.0.1
tag:tag0,option:dns-server,192.168.0.5,192.168.0.6""".lstrip()
        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf,
                              FakeV4MultipleAgentsWithoutDnsProvided(),
                              version=float(2.59))
            dm._output_opts_file()
        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_multiple_agents_with_dns_provided(self):
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:router,192.168.0.1""".lstrip()
        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf,
                              FakeV4MultipleAgentsWithDnsProvided(),
                              version=float(2.59))
            dm._output_opts_file()
        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_single_dhcp(self):
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,249,20.0.0.1/24,20.0.0.1
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
tag0,249,20.0.0.1/24,20.0.0.1
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
tag:tag0,249,169.254.169.254/32,192.168.1.1
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

    def test_output_opts_file_no_neutron_router_on_subnet(self):
        expected = """
tag:tag0,option:classless-static-route,169.254.169.254/32,192.168.1.2
tag:tag0,249,169.254.169.254/32,192.168.1.2
tag:tag0,option:router,192.168.1.1""".lstrip()

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeV4NetworkNoRouter(),
                              version=float(2.59))
            with mock.patch.object(dm, '_make_subnet_interface_ip_map') as ipm:
                ipm.return_value = {FakeV4SubnetNoRouter.id: '192.168.1.2'}

                dm._output_opts_file()
                self.assertTrue(ipm.called)

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_pxe_2port_1net(self):
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,249,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:tftp-server,192.168.0.3
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:server-ip-address,192.168.0.2
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:bootfile-name,pxelinux.0
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:tftp-server,192.168.0.3
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:server-ip-address,192.168.0.2
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:bootfile-name,pxelinux.0"""
        expected = expected.lstrip()

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            fp = FakeV4NetworkPxe2Ports()
            dm = dhcp.Dnsmasq(self.conf, fp, version=float(2.59))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_pxe_2port_1net_diff_details(self):
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,249,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:tftp-server,192.168.0.3
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:server-ip-address,192.168.0.2
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:bootfile-name,pxelinux.0
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:tftp-server,192.168.0.5
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:server-ip-address,192.168.0.5
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:bootfile-name,pxelinux.0"""
        expected = expected.lstrip()

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeV4NetworkPxe2Ports("portsDiff"),
                              version=float(2.59))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_pxe_3port_1net_diff_details(self):
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,249,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:tftp-server,192.168.0.3
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:server-ip-address,192.168.0.2
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:bootfile-name,pxelinux.0
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:tftp-server,192.168.0.5
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:server-ip-address,192.168.0.5
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:bootfile-name,pxelinux2.0
tag:44444444-4444-4444-4444-444444444444,option:tftp-server,192.168.0.7
tag:44444444-4444-4444-4444-444444444444,option:server-ip-address,192.168.0.7
tag:44444444-4444-4444-4444-444444444444,option:bootfile-name,pxelinux3.0"""
        expected = expected.lstrip()

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf,
                              FakeV4NetworkPxe3Ports("portsDifferent"),
                              version=float(2.59))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_pxe_3port_2net(self):
        expected = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,249,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:tftp-server,192.168.0.3
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:server-ip-address,192.168.0.2
tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,option:bootfile-name,pxelinux.0
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:tftp-server,192.168.1.3
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:server-ip-address,192.168.1.2
tag:ffffffff-ffff-ffff-ffff-ffffffffffff,option:bootfile-name,pxelinux2.0
tag:44444444-4444-4444-4444-444444444444,option:tftp-server,192.168.1.3
tag:44444444-4444-4444-4444-444444444444,option:server-ip-address,192.168.1.2
tag:44444444-4444-4444-4444-444444444444,option:bootfile-name,pxelinux3.0"""
        expected = expected.lstrip()

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = dhcp.Dnsmasq(self.conf, FakeDualV4Pxe3Ports(),
                              version=float(2.59))
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    @property
    def _test_reload_allocation_data(self):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal,'
                         '192.168.0.2\n'
                         '00:00:f3:aa:bb:cc,host-fdca-3ba5-a17a-4ba3--2.'
                         'openstacklocal,[fdca:3ba5:a17a:4ba3::2]\n'
                         '00:00:0f:aa:bb:cc,host-192-168-0-3.openstacklocal,'
                         '192.168.0.3\n'
                         '00:00:0f:aa:bb:cc,host-fdca-3ba5-a17a-4ba3--3.'
                         'openstacklocal,[fdca:3ba5:a17a:4ba3::3]\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1.openstacklocal,'
                         '192.168.0.1\n').lstrip()
        exp_addn_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/addn_hosts'
        exp_addn_data = (
            '192.168.0.2\t'
            'host-192-168-0-2.openstacklocal host-192-168-0-2\n'
            'fdca:3ba5:a17a:4ba3::2\t'
            'host-fdca-3ba5-a17a-4ba3--2.openstacklocal '
            'host-fdca-3ba5-a17a-4ba3--2\n'
            '192.168.0.3\thost-192-168-0-3.openstacklocal '
            'host-192-168-0-3\n'
            'fdca:3ba5:a17a:4ba3::3\t'
            'host-fdca-3ba5-a17a-4ba3--3.openstacklocal '
            'host-fdca-3ba5-a17a-4ba3--3\n'
            '192.168.0.1\t'
            'host-192-168-0-1.openstacklocal '
            'host-192-168-0-1\n'
        ).lstrip()
        exp_opt_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts'
        fake_v6 = 'gdca:3ba5:a17a:4ba3::1'
        fake_v6_cidr = 'gdca:3ba5:a17a:4ba3::/64'
        exp_opt_data = """
tag:tag0,option:dns-server,8.8.8.8
tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1
tag:tag0,249,20.0.0.1/24,20.0.0.1
tag:tag0,option:router,192.168.0.1
tag:tag1,option:dns-server,%s
tag:tag1,option:classless-static-route,%s,%s
tag:tag1,249,%s,%s""".lstrip() % (fake_v6,
                                  fake_v6_cidr, fake_v6,
                                  fake_v6_cidr, fake_v6)
        return (exp_host_name, exp_host_data,
                exp_addn_name, exp_addn_data,
                exp_opt_name, exp_opt_data,)

    def test_reload_allocations(self):
        (exp_host_name, exp_host_data,
         exp_addn_name, exp_addn_data,
         exp_opt_name, exp_opt_data,) = self._test_reload_allocation_data

        exp_args = ['kill', '-HUP', 5]

        fake_net = FakeDualNetwork()
        dm = dhcp.Dnsmasq(self.conf, fake_net, version=float(2.59))

        with contextlib.nested(
            mock.patch('os.path.isdir', return_value=True),
            mock.patch.object(dhcp.Dnsmasq, 'active'),
            mock.patch.object(dhcp.Dnsmasq, 'pid'),
            mock.patch.object(dhcp.Dnsmasq, 'interface_name'),
            mock.patch.object(dhcp.Dnsmasq, '_make_subnet_interface_ip_map'),
            mock.patch.object(dm, 'device_manager')
        ) as (isdir, active, pid, interface_name, ip_map, device_manager):
            active.__get__ = mock.Mock(return_value=True)
            pid.__get__ = mock.Mock(return_value=5)
            interface_name.__get__ = mock.Mock(return_value='tap12345678-12')
            ip_map.return_value = {}
            dm.reload_allocations()

        self.assertTrue(ip_map.called)
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_addn_name, exp_addn_data),
                                    mock.call(exp_opt_name, exp_opt_data)])
        self.execute.assert_called_once_with(exp_args, 'sudo')
        device_manager.update.assert_called_with(fake_net, 'tap12345678-12')

    def test_reload_allocations_stale_pid(self):
        (exp_host_name, exp_host_data,
         exp_addn_name, exp_addn_data,
         exp_opt_name, exp_opt_data,) = self._test_reload_allocation_data

        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.readline.return_value = None

            with mock.patch('os.path.isdir') as isdir:
                isdir.return_value = True
                with mock.patch.object(dhcp.Dnsmasq, 'pid') as pid:
                    pid.__get__ = mock.Mock(return_value=5)
                    dm = dhcp.Dnsmasq(self.conf, FakeDualNetwork(),
                                      version=float(2.59))

                    method_name = '_make_subnet_interface_ip_map'
                    with mock.patch.object(dhcp.Dnsmasq, method_name) as ipmap:
                        ipmap.return_value = {}
                        with mock.patch.object(dhcp.Dnsmasq, 'interface_name'):
                            dm.reload_allocations()
                            self.assertTrue(ipmap.called)

            self.safe.assert_has_calls([
                mock.call(exp_host_name, exp_host_data),
                mock.call(exp_addn_name, exp_addn_data),
                mock.call(exp_opt_name, exp_opt_data),
            ])
            mock_open.assert_called_once_with('/proc/5/cmdline', 'r')

    def test_release_unused_leases(self):
        dnsmasq = dhcp.Dnsmasq(self.conf, FakeDualNetwork())

        ip1 = '192.168.1.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.1.3'
        mac2 = '00:00:80:cc:bb:aa'

        old_leases = set([(ip1, mac1), (ip2, mac2)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = []

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_has_calls([mock.call(mac1, ip1),
                                                 mock.call(mac2, ip2)],
                                                any_order=True)

    def test_release_unused_leases_one_lease(self):
        dnsmasq = dhcp.Dnsmasq(self.conf, FakeDualNetwork())

        ip1 = '192.168.0.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.0.3'
        mac2 = '00:00:80:cc:bb:aa'

        old_leases = set([(ip1, mac1), (ip2, mac2)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = [FakePort1()]

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_has_calls([mock.call(mac2, ip2)],
                                                any_order=True)

    def test_read_hosts_file_leases(self):
        filename = '/path/to/file'
        with mock.patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            with mock.patch('__builtin__.open') as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = mock.Mock()
                lines = ["00:00:80:aa:bb:cc,inst-name,192.168.0.1"]
                mock_open.return_value.readlines.return_value = lines

                dnsmasq = dhcp.Dnsmasq(self.conf, FakeDualNetwork())
                leases = dnsmasq._read_hosts_file_leases(filename)

        self.assertEqual(set([("192.168.0.1", "00:00:80:aa:bb:cc")]), leases)
        mock_exists.assert_called_once_with(filename)
        mock_open.assert_called_once_with(filename)

    def test_make_subnet_interface_ip_map(self):
        with mock.patch('neutron.agent.linux.ip_lib.IPDevice') as ip_dev:
            ip_dev.return_value.addr.list.return_value = [
                {'cidr': '192.168.0.1/24'}
            ]

            dm = dhcp.Dnsmasq(self.conf,
                              FakeDualNetwork())

            self.assertEqual(
                dm._make_subnet_interface_ip_map(),
                {FakeV4Subnet.id: '192.168.0.1'}
            )

    def test_remove_config_files(self):
        net = FakeV4Network()
        path = '/opt/data/neutron/dhcp'
        self.conf.dhcp_confs = path

        with mock.patch('shutil.rmtree') as rmtree:
            lp = LocalChild(self.conf, net)
            lp._remove_config_files()

            rmtree.assert_called_once_with(os.path.join(path, net.id),
                                           ignore_errors=True)

    def test_existing_dhcp_networks(self):
        path = '/opt/data/neutron/dhcp'
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
                self.assertEqual(['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                  'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'],
                                 result)

    def _check_version(self, cmd_out, expected_value):
        with mock.patch('neutron.agent.linux.utils.execute') as cmd:
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
