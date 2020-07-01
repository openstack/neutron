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
from neutron_lib import constants
from oslo_utils import excutils
from pyroute2.netlink import exceptions as pyroute2_exc

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ethtool
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron.conf.agent import common as config
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_const
from neutron.tests import base


class BaseChild(interface.LinuxInterfaceDriver):
    def plug_new(*args):
        pass

    def unplug(*args):
        pass


class FakeNetwork(object):
    id = '12345678-1234-5678-90ab-ba0987654321'


class FakeSubnet(object):
    cidr = '192.168.1.1/24'


class FakeAllocation(object):
    subnet = FakeSubnet()
    ip_address = '192.168.1.2'
    ip_version = constants.IP_VERSION_4


class FakePort(object):
    id = 'abcdef01-1234-5678-90ab-ba0987654321'
    fixed_ips = [FakeAllocation]
    device_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    network = FakeNetwork()
    network_id = network.id


class FakeLegacyInterfaceDriver(interface.LinuxInterfaceDriver):

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None, mtu=None):
        """This is legacy method which don't accepts link_up argument."""
        pass

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        pass


class TestBase(base.BaseTestCase):
    def setUp(self):
        super(TestBase, self).setUp()
        self.conf = config.setup_conf()
        ovs_conf.register_ovs_opts(self.conf)
        config.register_interface_opts(self.conf)
        self.eth_tool_p = mock.patch.object(ethtool, 'Ethtool')
        self.eth_tool = self.eth_tool_p.start()
        self.ip_dev_p = mock.patch.object(ip_lib, 'IPDevice')
        self.ip_dev = self.ip_dev_p.start()
        self.ip_p = mock.patch.object(ip_lib, 'IPWrapper')
        self.ip = self.ip_p.start()
        self.device_exists_p = mock.patch.object(ip_lib, 'device_exists')
        self.device_exists = self.device_exists_p.start()
        self.get_devices_with_ip_p = mock.patch.object(ip_lib,
                                                       'get_devices_with_ip')
        self.get_devices_with_ip = self.get_devices_with_ip_p.start()


class TestABCDriver(TestBase):
    def setUp(self):
        super(TestABCDriver, self).setUp()
        mock_link_addr = mock.PropertyMock(return_value='aa:bb:cc:dd:ee:ff')
        type(self.ip_dev().link).address = mock_link_addr

    def test_get_device_name(self):
        bc = BaseChild(self.conf)
        device_name = bc.get_device_name(FakePort())
        self.assertEqual('tapabcdef01-12', device_name)

    def test_init_router_port(self):
        addresses = [dict(scope='global',
                          dynamic=False, cidr='172.16.77.240/24')]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)
        self.ip_dev().route.list_onlink_routes.return_value = []

        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc.init_router_port('tap0', ['192.168.1.2/24'], namespace=ns,
                            extra_subnets=[{'cidr': '172.20.0.0/24'}])
        self.ip_dev.assert_has_calls(
            [mock.call('tap0', namespace=ns),
             mock.call().addr.list(),
             mock.call().addr.delete('172.16.77.240/24'),
             mock.call().addr.add('192.168.1.2/24'),
             mock.call('tap0', namespace=ns),
             mock.call().route.list_onlink_routes(constants.IP_VERSION_4),
             mock.call().route.list_onlink_routes(constants.IP_VERSION_6),
             mock.call().route.add_onlink_route('172.20.0.0/24')])

    def test_init_router_port_delete_onlink_routes(self):
        addresses = [dict(scope='global',
                          dynamic=False, cidr='172.16.77.240/24')]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)
        self.ip_dev().route.list_onlink_routes.return_value = [
            {'cidr': '172.20.0.0/24'}]

        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc.init_router_port('tap0', ['192.168.1.2/24'], namespace=ns)
        self.ip_dev.assert_has_calls(
            [mock.call().route.list_onlink_routes(constants.IP_VERSION_4),
             mock.call().route.list_onlink_routes(constants.IP_VERSION_6),
             mock.call().route.delete_onlink_route('172.20.0.0/24')])

    def test_l3_init_with_preserve(self):
        addresses = [dict(scope='global',
                          dynamic=False, cidr='192.168.1.3/32')]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)

        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc.init_l3('tap0', ['192.168.1.2/24'], namespace=ns,
                   preserve_ips=['192.168.1.3/32'])
        self.ip_dev.assert_has_calls(
            [mock.call('tap0', namespace=ns),
             mock.call().addr.list(),
             mock.call().addr.add('192.168.1.2/24')])
        self.assertFalse(self.ip_dev().addr.delete.called)
        self.assertFalse(self.ip_dev().delete_addr_and_conntrack_state.called)

    def _test_l3_init_clean_connections(self, clean_connections):
        addresses = [
            dict(scope='global', dynamic=False, cidr='10.0.0.1/24'),
            dict(scope='global', dynamic=False, cidr='10.0.0.3/32')]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)

        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc.init_l3('tap0', ['10.0.0.1/24'], namespace=ns,
                   clean_connections=clean_connections)

        delete = self.ip_dev().delete_addr_and_conntrack_state
        if clean_connections:
            delete.assert_called_once_with('10.0.0.3/32')
        else:
            self.assertFalse(delete.called)

    def test_l3_init_with_clean_connections(self):
        self._test_l3_init_clean_connections(True)

    def test_l3_init_without_clean_connections(self):
        self._test_l3_init_clean_connections(False)

    def test_init_router_port_ipv6_with_gw_ip(self):
        addresses = [dict(scope='global',
                          dynamic=False,
                          cidr='2001:db8:a::123/64')]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)
        self.ip_dev().route.list_onlink_routes.return_value = []

        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        new_cidr = '2001:db8:a::124/64'
        kwargs = {'namespace': ns,
                  'extra_subnets': [{'cidr': '2001:db8:b::/64'}]}
        bc.init_router_port('tap0', [new_cidr], **kwargs)
        expected_calls = (
            [mock.call('tap0', namespace=ns),
             mock.call().addr.list(),
             mock.call().addr.delete('2001:db8:a::123/64'),
             mock.call().addr.add('2001:db8:a::124/64')])
        expected_calls += (
             [mock.call('tap0', namespace=ns),
              mock.call().route.list_onlink_routes(constants.IP_VERSION_4),
              mock.call().route.list_onlink_routes(constants.IP_VERSION_6),
              mock.call().route.add_onlink_route('2001:db8:b::/64')])
        self.ip_dev.assert_has_calls(expected_calls)

    def test_init_router_port_ext_gw_with_dual_stack(self):
        old_addrs = [dict(ip_version=constants.IP_VERSION_4, scope='global',
                          dynamic=False, cidr='172.16.77.240/24'),
                     dict(ip_version=constants.IP_VERSION_6, scope='global',
                          dynamic=False, cidr='2001:db8:a::123/64')]
        self.ip_dev().addr.list = mock.Mock(return_value=old_addrs)
        self.ip_dev().route.list_onlink_routes.return_value = []
        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        new_cidrs = ['192.168.1.2/24', '2001:db8:a::124/64']
        bc.init_router_port('tap0', new_cidrs, namespace=ns,
            extra_subnets=[{'cidr': '172.20.0.0/24'}])
        self.ip_dev.assert_has_calls(
            [mock.call('tap0', namespace=ns),
             mock.call().addr.list(),
             mock.call().addr.add('192.168.1.2/24'),
             mock.call().addr.add('2001:db8:a::124/64'),
             mock.call().addr.delete('172.16.77.240/24'),
             mock.call().addr.delete('2001:db8:a::123/64'),
             mock.call().route.list_onlink_routes(constants.IP_VERSION_4),
             mock.call().route.list_onlink_routes(constants.IP_VERSION_6),
             mock.call().route.add_onlink_route('172.20.0.0/24')],
            any_order=True)

    def test_init_router_port_with_ipv6_delete_onlink_routes(self):
        addresses = [dict(scope='global',
                          dynamic=False, cidr='2001:db8:a::123/64')]
        route = '2001:db8:a::/64'
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)
        self.ip_dev().route.list_onlink_routes.return_value = [{'cidr': route}]

        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc.init_router_port('tap0', ['2001:db8:a::124/64'], namespace=ns)
        self.ip_dev.assert_has_calls(
            [mock.call().route.list_onlink_routes(constants.IP_VERSION_4),
             mock.call().route.list_onlink_routes(constants.IP_VERSION_6),
             mock.call().route.delete_onlink_route(route)])

    def test_l3_init_with_duplicated_ipv6(self):
        addresses = [dict(scope='global',
                          dynamic=False,
                          cidr='2001:db8:a::123/64')]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)
        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc.init_l3('tap0', ['2001:db8:a::123/64'], namespace=ns)
        self.assertFalse(self.ip_dev().addr.add.called)

    def test_l3_init_with_duplicated_ipv6_uncompact(self):
        addresses = [dict(scope='global',
                          dynamic=False,
                          cidr='2001:db8:a::123/64')]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)
        bc = BaseChild(self.conf)
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc.init_l3('tap0',
                   ['2001:db8:a:0000:0000:0000:0000:0123/64'],
                   namespace=ns)
        self.assertFalse(self.ip_dev().addr.add.called)

    def test_l3_init_with_duplicated_ipv6_dynamic(self):
        device_name = 'tap0'
        cidr = '2001:db8:a::123/64'
        ns = '12345678-1234-5678-90ab-ba0987654321'
        addresses = [dict(scope='global',
                          dynamic=True,
                          cidr=cidr)]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)
        bc = BaseChild(self.conf)
        bc.init_l3(device_name, [cidr], namespace=ns)
        self.ip_dev.assert_has_calls(
            [mock.call(device_name, namespace=ns),
             mock.call().addr.list(),
             mock.call().addr.delete(cidr),
             mock.call().addr.add(cidr)])

    def test_l3_init_with_duplicated_ipv6_lla(self):
        device_name = 'tap0'
        cidr = 'fe80::a8bb:ccff:fedd:eeff/64'
        ns = '12345678-1234-5678-90ab-ba0987654321'
        addresses = [dict(scope='link',
                          dynamic=False,
                          cidr=cidr)]
        self.ip_dev().addr.list = mock.Mock(return_value=addresses)
        bc = BaseChild(self.conf)
        bc.init_l3(device_name, [cidr], namespace=ns)
        self.ip_dev.assert_has_calls(
            [mock.call(device_name, namespace=ns),
             mock.call().addr.list()])
        # The above assert won't verify there were no extra calls right
        # after list()
        self.assertFalse(self.ip_dev().addr.add.called)

    def test_l3_init_with_not_present_ipv6_lla(self):
        device_name = 'tap0'
        cidr = 'fe80::a8bb:ccff:fedd:eeff/64'
        ns = '12345678-1234-5678-90ab-ba0987654321'
        self.ip_dev().addr.list = mock.Mock(return_value=[])
        bc = BaseChild(self.conf)
        bc.init_l3(device_name, [cidr], namespace=ns)
        self.ip_dev.assert_has_calls(
            [mock.call(device_name, namespace=ns),
             mock.call().addr.list(),
             mock.call().addr.add(cidr)])

    def test_add_ipv6_addr(self):
        device_name = 'tap0'
        cidr = '2001:db8::/64'
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc = BaseChild(self.conf)

        bc.add_ipv6_addr(device_name, cidr, ns)

        self.ip_dev.assert_has_calls(
            [mock.call(device_name, namespace=ns),
             mock.call().addr.add(cidr, 'global')])

    def test_delete_ipv6_addr(self):
        device_name = 'tap0'
        cidr = '2001:db8::/64'
        ns = '12345678-1234-5678-90ab-ba0987654321'
        bc = BaseChild(self.conf)

        bc.delete_ipv6_addr(device_name, cidr, ns)

        self.ip_dev.assert_has_calls(
            [mock.call(device_name, namespace=ns),
             mock.call().delete_addr_and_conntrack_state(cidr)])

    def test_delete_ipv6_addr_with_prefix(self):
        device_name = 'tap0'
        prefix = '2001:db8::/48'
        in_cidr = '2001:db8::/64'
        out_cidr = '2001:db7::/64'
        ns = '12345678-1234-5678-90ab-ba0987654321'
        in_addresses = [dict(scope='global',
                        dynamic=False,
                        cidr=in_cidr)]
        out_addresses = [dict(scope='global',
                         dynamic=False,
                         cidr=out_cidr)]
        # Initially set the address list to be empty
        self.ip_dev().addr.list = mock.Mock(return_value=[])

        bc = BaseChild(self.conf)

        # Call delete_v6addr_with_prefix when the address list is empty
        bc.delete_ipv6_addr_with_prefix(device_name, prefix, ns)
        # Assert that delete isn't called
        self.assertFalse(self.ip_dev().delete_addr_and_conntrack_state.called)

        # Set the address list to contain only an address outside of the range
        # of the given prefix
        self.ip_dev().addr.list = mock.Mock(return_value=out_addresses)
        bc.delete_ipv6_addr_with_prefix(device_name, prefix, ns)
        # Assert that delete isn't called
        self.assertFalse(self.ip_dev().delete_addr_and_conntrack_state.called)

        # Set the address list to contain only an address inside of the range
        # of the given prefix
        self.ip_dev().addr.list = mock.Mock(return_value=in_addresses)
        bc.delete_ipv6_addr_with_prefix(device_name, prefix, ns)
        # Assert that delete is called
        self.ip_dev.assert_has_calls(
            [mock.call(device_name, namespace=ns),
             mock.call().addr.list(scope='global', filters=['permanent']),
             mock.call().delete_addr_and_conntrack_state(in_cidr)])

    def test_get_ipv6_llas(self):
        ns = '12345678-1234-5678-90ab-ba0987654321'
        addresses = [dict(scope='link',
                          dynamic=False,
                          cidr='fe80:cafe::/64')]
        self.get_devices_with_ip.return_value = addresses
        device_name = self.ip_dev().name
        bc = BaseChild(self.conf)

        llas = bc.get_ipv6_llas(device_name, ns)

        self.assertEqual(addresses, llas)
        kwargs = {'family': utils.get_socket_address_family(
                                constants.IP_VERSION_6),
                  'scope': 'link'}
        self.get_devices_with_ip.assert_called_with(
            ns, name=device_name, **kwargs)

    def test_set_mtu_logs_once(self):
        bc = BaseChild(self.conf)
        with mock.patch('neutron.agent.linux.interface.LOG.warning') as log:
            bc.set_mtu('dev', 9999)
            log.assert_called_once_with(mock.ANY)


class TestOVSInterfaceDriver(TestBase):

    def test_get_device_name(self):
        br = interface.OVSInterfaceDriver(self.conf)
        device_name = br.get_device_name(FakePort())
        self.assertEqual('tapabcdef01-12', device_name)

    def test_plug_no_ns(self):
        self._test_plug()

    def test_plug_with_ns(self):
        self._test_plug(namespace='01234567-1234-1234-99')

    def test_plug_alt_bridge(self):
        self._test_plug(bridge='br-foo')

    def test_plug_configured_bridge(self):
        br = 'br-v'
        self.conf.set_override('ovs_use_veth', False)
        self.conf.set_override('integration_bridge', br, 'OVS')
        self.assertEqual(self.conf.OVS.integration_bridge, br)

        def device_exists(dev, namespace=None):
            return dev == br

        ovs = interface.OVSInterfaceDriver(self.conf)
        with mock.patch.object(ovs, '_ovs_add_port') as add_port:
            self.device_exists.side_effect = device_exists
            ovs.plug('01234567-1234-1234-99',
                     'port-1234',
                     'tap0',
                     'aa:bb:cc:dd:ee:ff',
                     bridge=None,
                     namespace=None)

        add_port.assert_called_once_with('br-v',
                                         'tap0',
                                         'port-1234',
                                         'aa:bb:cc:dd:ee:ff',
                                         internal=True)

    def _test_plug(self, bridge=None, namespace=None):
        with mock.patch('neutron.agent.ovsdb.impl_idl._connection'):
            if not bridge:
                bridge = 'br-int'

            def device_exists(dev, namespace=None):
                return dev == bridge

            with mock.patch.object(ovs_lib.OVSBridge,
                                   'replace_port') as replace:
                ovs = interface.OVSInterfaceDriver(self.conf)
                self.device_exists.side_effect = device_exists
                link = self.ip.return_value.device.return_value.link
                link.set_address.side_effect = (RuntimeError, None)
                ovs.plug('01234567-1234-1234-99',
                         'port-1234',
                         'tap0',
                         'aa:bb:cc:dd:ee:ff',
                         bridge=bridge,
                         namespace=namespace,
                         mtu=9000)
                replace.assert_called_once_with(
                    'tap0',
                    ('type', 'internal'),
                    ('external_ids', {
                        'iface-id': 'port-1234',
                        'iface-status': 'active',
                        'attached-mac': 'aa:bb:cc:dd:ee:ff'}))

            expected = [
                mock.call(),
                mock.call().device('tap0'),
                mock.call().device().link.set_address('aa:bb:cc:dd:ee:ff'),
                mock.call().device().link.set_address('aa:bb:cc:dd:ee:ff')]
            if namespace:
                expected.extend(
                    [mock.call().ensure_namespace(namespace),
                     mock.call().ensure_namespace().add_device_to_namespace(
                         mock.ANY)])
            expected.extend([
                mock.call(namespace=namespace),
                mock.call().device('tap0'),
                mock.call().device().link.set_mtu(9000),
                mock.call().device().link.set_up(),
            ])

            self.ip.assert_has_calls(expected)

    def test_plug_new(self):
        with mock.patch('neutron.agent.ovsdb.impl_idl._connection'):
            bridge = 'br-int'
            namespace = '01234567-1234-1234-99'
            with mock.patch.object(ovs_lib.OVSBridge,
                                   'delete_port') as delete_port:
                with mock.patch.object(ovs_lib.OVSBridge, 'replace_port'):
                    ovs = interface.OVSInterfaceDriver(self.conf)
                    reraise = mock.patch.object(
                        excutils, 'save_and_reraise_exception')
                    reraise.start()
                    ip_wrapper = mock.Mock()
                    for exception in (OSError(),
                                      pyroute2_exc.NetlinkError(22)):
                        ip_wrapper.ensure_namespace.side_effect = exception
                        self.ip.return_value = ip_wrapper
                        delete_port.reset_mock()
                        ovs.plug_new(
                            '01234567-1234-1234-99',
                            'port-1234',
                            'tap0',
                            'aa:bb:cc:dd:ee:ff',
                            bridge=bridge,
                            namespace=namespace,
                            prefix='veth',
                            mtu=9000)
                        delete_port.assert_called_once_with('tap0')

    def test_unplug(self):
        with mock.patch('neutron.agent.common.ovs_lib.OVSBridge') as ovs_br:
            ovs = interface.OVSInterfaceDriver(self.conf)
            ovs.unplug('tap0')
            ovs_br.assert_has_calls([mock.call('br-int'),
                                     mock.call().delete_port('tap0')])


class TestOVSInterfaceDriverWithVeth(TestOVSInterfaceDriver):

    def setUp(self):
        super(TestOVSInterfaceDriverWithVeth, self).setUp()
        ovs_conf.register_ovs_agent_opts(self.conf)
        self.conf.set_override('ovs_use_veth', True)
        self.conf.set_override(
            'datapath_type',
            ovs_const.OVS_DATAPATH_NETDEV,
            group='OVS')

    def test_get_device_name(self):
        br = interface.OVSInterfaceDriver(self.conf)
        device_name = br.get_device_name(FakePort())
        self.assertEqual('ns-abcdef01-12', device_name)

    def test_plug_with_prefix(self):
        self._test_plug(devname='qr-0', prefix='qr-')

    def _test_plug(self, devname=None, bridge=None, namespace=None,
                   prefix=None):
        with mock.patch('neutron.agent.ovsdb.impl_idl._connection'):

            if not devname:
                devname = 'ns-0'
            if not bridge:
                bridge = 'br-int'

            def device_exists(dev, namespace=None):
                return dev == bridge

            ovs = interface.OVSInterfaceDriver(self.conf)
            self.device_exists.side_effect = device_exists

            root_dev = mock.Mock()
            ns_dev = mock.Mock()
            self.ip().add_veth = mock.Mock(return_value=(root_dev, ns_dev))
            mock.patch.object(
                interface, '_get_veth',
                return_value=(root_dev, ns_dev)).start()
            ns_dev.name = devname

            expected = [mock.call(),
                        mock.call().add_veth('tap0', devname,
                                             namespace2=namespace)]

            with mock.patch.object(ovs_lib.OVSBridge,
                                   'replace_port') as replace:
                ovs.plug('01234567-1234-1234-99',
                         'port-1234',
                         devname,
                         'aa:bb:cc:dd:ee:ff',
                         bridge=bridge,
                         namespace=namespace,
                         prefix=prefix,
                         mtu=9000)
                replace.assert_called_once_with(
                    'tap0',
                    ('external_ids', {
                        'iface-id': 'port-1234',
                        'iface-status': 'active',
                        'attached-mac': 'aa:bb:cc:dd:ee:ff'}))

            ns_dev.assert_has_calls(
                [mock.call.link.set_address('aa:bb:cc:dd:ee:ff')])
            ns_dev.assert_has_calls([mock.call.link.set_mtu(9000)])
            root_dev.assert_has_calls([mock.call.link.set_mtu(9000)])

            self.ip.assert_has_calls(expected)
            root_dev.assert_has_calls([mock.call.link.set_up()])
            ns_dev.assert_has_calls([mock.call.link.set_up()])
            self.eth_tool.assert_has_calls([mock.call.offload(
                                            devname, rx=False,
                                            tx=False, namespace=namespace)])

    def test_plug_new(self):
        # The purpose of test_plug_new in parent class(TestOVSInterfaceDriver)
        # is to test exception(exceptions.ProcessExecutionError), method here
        # would not go through that code, So just pass
        pass

    def test_unplug(self):
        bridge = 'br-int'
        with mock.patch('neutron.agent.common.ovs_lib.OVSBridge') as ovs_br:
            ovs = interface.OVSInterfaceDriver(self.conf)
            ovs.unplug('ns-0', bridge=bridge)
            ovs_br.assert_has_calls([mock.call(bridge),
                                     mock.call().delete_port('tap0')])
        self.ip_dev.assert_has_calls([mock.call('ns-0', namespace=None),
                                      mock.call().link.delete()])


class TestBridgeInterfaceDriver(TestBase):
    def test_get_device_name(self):
        br = interface.BridgeInterfaceDriver(self.conf)
        device_name = br.get_device_name(FakePort())
        self.assertEqual('ns-abcdef01-12', device_name)

    def test_plug_no_ns(self):
        self._test_plug()

    def test_plug_with_ns(self):
        self._test_plug(namespace='01234567-1234-1234-99')

    def _test_plug(self, namespace=None):
        def device_exists(device, namespace=None):
            return device.startswith('brq')

        root_veth = mock.Mock()
        ns_veth = mock.Mock()

        self.ip().add_veth = mock.Mock(return_value=(root_veth, ns_veth))
        mock.patch.object(
            interface, '_get_veth',
            return_value=(root_veth, ns_veth)).start()

        self.device_exists.side_effect = device_exists
        br = interface.BridgeInterfaceDriver(self.conf)
        mac_address = 'aa:bb:cc:dd:ee:ff'
        br.plug('01234567-1234-1234-99',
                'port-1234',
                'ns-0',
                mac_address,
                namespace=namespace,
                mtu=9000)

        ip_calls = [mock.call(),
                    mock.call().add_veth('tap0', 'ns-0', namespace2=namespace)]
        ns_veth.assert_has_calls([mock.call.link.set_address(mac_address)])
        ns_veth.assert_has_calls([mock.call.link.set_mtu(9000)])
        root_veth.assert_has_calls([mock.call.link.set_mtu(9000)])

        self.ip.assert_has_calls(ip_calls)

        root_veth.assert_has_calls([mock.call.link.set_up()])
        ns_veth.assert_has_calls([mock.call.link.set_up()])

    def test_plug_dev_exists(self):
        self.device_exists.return_value = True
        with mock.patch('neutron.agent.linux.interface.LOG.info') as log:
            br = interface.BridgeInterfaceDriver(self.conf)
            br.plug('01234567-1234-1234-99',
                    'port-1234',
                    'tap0',
                    'aa:bb:cc:dd:ee:ff')
            self.assertFalse(self.ip_dev.called)
            self.assertEqual(log.call_count, 1)

    def test_unplug_no_device(self):
        self.device_exists.return_value = False
        self.ip_dev().link.delete.side_effect = RuntimeError
        with mock.patch('neutron.agent.linux.interface.LOG') as log:
            br = interface.BridgeInterfaceDriver(self.conf)
            br.unplug('tap0')
            [mock.call(), mock.call('tap0'), mock.call().link.delete()]
            self.assertEqual(log.error.call_count, 1)

    def test_unplug(self):
        self.device_exists.return_value = True
        with mock.patch('neutron.agent.linux.interface.LOG.debug') as log:
            br = interface.BridgeInterfaceDriver(self.conf)
            br.unplug('tap0')
            self.assertEqual(log.call_count, 1)

        self.ip_dev.assert_has_calls([mock.call('tap0', namespace=None),
                                      mock.call().link.delete()])


class TestLegacyDriver(TestBase):

    def test_plug(self):
        self.device_exists.return_value = False
        with mock.patch('neutron.agent.linux.interface.LOG.warning') as log:
            driver = FakeLegacyInterfaceDriver(self.conf)
            try:
                driver.plug(
                    '01234567-1234-1234-99', 'port-1234', 'tap0',
                    'aa:bb:cc:dd:ee:ff')
            except TypeError:
                self.fail("LinuxInterfaceDriver class can not call properly "
                          "plug_new method from the legacy drivers that "
                          "do not accept 'link_up' parameter.")
            log.assert_called_once()
