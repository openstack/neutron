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

import uuid

import mock
import unittest2 as unittest

from quantum.agent import dhcp_agent
from quantum.agent.common import config
from quantum.agent.linux import interface
from quantum.common import exceptions
from quantum.openstack.common import cfg


class FakeModel:
    def __init__(self, id_, **kwargs):
        self.id = id_
        self.__dict__.update(kwargs)

    def __str__(self):
        return str(self.__dict__)


fake_subnet1 = FakeModel('bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb',
                         network_id='12345678-1234-5678-1234567890ab',
                         cidr='172.9.9.0/24', enable_dhcp=True)

fake_subnet2 = FakeModel('dddddddd-dddd-dddd-dddddddddddd',
                         network_id='12345678-1234-5678-1234567890ab',
                         enable_dhcp=False)

fake_fixed_ip = FakeModel('', subnet=fake_subnet1, ip_address='172.9.9.9')

fake_port1 = FakeModel('12345678-1234-aaaa-1234567890ab',
                       mac_address='aa:bb:cc:dd:ee:ff',
                       network_id='12345678-1234-5678-1234567890ab',
                       fixed_ips=[fake_fixed_ip])

fake_port2 = FakeModel('12345678-1234-aaaa-123456789000',
                       mac_address='aa:bb:cc:dd:ee:99',
                       network_id='12345678-1234-5678-1234567890ab')

fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                         tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                         admin_state_up=True,
                         subnets=[fake_subnet1, fake_subnet2],
                         ports=[fake_port1])

fake_down_network = FakeModel('12345678-dddd-dddd-1234567890ab',
                              tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                              admin_state_up=False,
                              subnets=[],
                              ports=[])


class TestDhcpAgent(unittest.TestCase):
    def setUp(self):
        cfg.CONF.register_opts(dhcp_agent.DhcpAgent.OPTS)
        self.driver_cls_p = mock.patch(
            'quantum.agent.dhcp_agent.importutils.import_class')
        self.driver = mock.Mock(name='driver')
        self.driver_cls = self.driver_cls_p.start()
        self.driver_cls.return_value = self.driver
        self.notification_p = mock.patch(
            'quantum.agent.rpc.NotificationDispatcher')
        self.notification = self.notification_p.start()

    def tearDown(self):
        self.notification_p.stop()
        self.driver_cls_p.stop()

    def test_dhcp_agent_main(self):
        with mock.patch('quantum.agent.dhcp_agent.DeviceManager') as dev_mgr:
            with mock.patch('quantum.agent.dhcp_agent.DhcpAgent') as dhcp:
                with mock.patch('quantum.agent.dhcp_agent.sys') as mock_sys:
                    mock_sys.argv = []
                    dhcp_agent.main()
                    dev_mgr.assert_called_once(mock.ANY, 'sudo')
                    dhcp.assert_has_calls([
                        mock.call(mock.ANY),
                        mock.call().run()])

    def test_run_completes_single_pass(self):
        with mock.patch('quantum.agent.dhcp_agent.DeviceManager') as dev_mgr:
            with mock.patch('quantum.agent.dhcp_agent.DhcpPluginApi') as plug:
                mock_plugin = mock.Mock()
                mock_plugin.get_active_networks.return_value = ['a']
                plug.return_value = mock_plugin

                dhcp = dhcp_agent.DhcpAgent(cfg.CONF)
                with mock.patch.object(dhcp, 'enable_dhcp_helper') as enable:
                    dhcp.run()
                    enable.assert_called_once_with('a')
                    plug.assert_called_once_with('q-plugin', mock.ANY)
                    mock_plugin.assert_has_calls(
                        [mock.call.get_active_networks()])

        self.notification.assert_has_calls([mock.call.run_dispatch()])

    def test_call_driver(self):
        with mock.patch('quantum.agent.dhcp_agent.DeviceManager') as dev_mgr:
            dhcp = dhcp_agent.DhcpAgent(cfg.CONF)
            dhcp.call_driver('foo', '1')
            dev_mgr.assert_called()
            self.driver.assert_called_once_with(cfg.CONF,
                                                mock.ANY,
                                                'sudo',
                                                mock.ANY)


class TestDhcpAgentEventHandler(unittest.TestCase):
    def setUp(self):
        cfg.CONF.register_opts(dhcp_agent.DeviceManager.OPTS)
        cfg.CONF.set_override('interface_driver',
                              'quantum.agent.linux.interface.NullDriver')
        cfg.CONF.root_helper = 'sudo'
        cfg.CONF.register_opts(dhcp_agent.DhcpAgent.OPTS)
        self.notification_p = mock.patch(
            'quantum.agent.rpc.NotificationDispatcher')
        self.notification = self.notification_p.start()

        self.plugin_p = mock.patch('quantum.agent.dhcp_agent.DhcpPluginApi')
        plugin_cls = self.plugin_p.start()
        self.plugin = mock.Mock()
        plugin_cls.return_value = self.plugin

        self.cache_p = mock.patch('quantum.agent.dhcp_agent.NetworkCache')
        cache_cls = self.cache_p.start()
        self.cache = mock.Mock()
        cache_cls.return_value = self.cache

        self.dhcp = dhcp_agent.DhcpAgent(cfg.CONF)
        self.call_driver_p = mock.patch.object(self.dhcp, 'call_driver')

        self.call_driver = self.call_driver_p.start()

    def tearDown(self):
        self.call_driver_p.stop()
        self.cache_p.stop()
        self.plugin_p.stop()
        self.notification_p.stop()

    def test_enable_dhcp_helper(self):
        self.plugin.get_network_info.return_value = fake_network
        self.dhcp.enable_dhcp_helper(fake_network.id)
        self.plugin.assert_has_calls(
            [mock.call.get_network_info(fake_network.id)])
        self.call_driver.assert_called_once_with('enable', fake_network)

    def test_enable_dhcp_helper_down_network(self):
        self.plugin.get_network_info.return_value = fake_down_network
        self.dhcp.enable_dhcp_helper(fake_down_network.id)
        self.plugin.assert_has_calls(
            [mock.call.get_network_info(fake_down_network.id)])
        self.assertFalse(self.call_driver.called)

    def test_disable_dhcp_helper_known_network(self):
        self.cache.get_network_by_id.return_value = fake_network
        self.dhcp.disable_dhcp_helper(fake_network.id)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_network.id)])
        self.call_driver.assert_called_once_with('disable', fake_network)

    def test_disable_dhcp_helper_unknown_network(self):
        self.cache.get_network_by_id.return_value = None
        self.dhcp.disable_dhcp_helper('abcdef')
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id('abcdef')])
        self.assertEqual(self.call_driver.call_count, 0)

    def test_network_create_end(self):
        payload = dict(network=dict(id=fake_network.id))

        with mock.patch.object(self.dhcp, 'enable_dhcp_helper') as enable:
            self.dhcp.network_create_end(payload)
            enable.assertCalledOnceWith(fake_network.id)

    def test_network_update_end_admin_state_up(self):
        payload = dict(network=dict(id=fake_network.id, admin_state_up=True))
        with mock.patch.object(self.dhcp, 'enable_dhcp_helper') as enable:
            self.dhcp.network_update_end(payload)
            enable.assertCalledOnceWith(fake_network.id)

    def test_network_update_end_admin_state_down(self):
        payload = dict(network=dict(id=fake_network.id, admin_state_up=False))
        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.network_update_end(payload)
            disable.assertCalledOnceWith(fake_network.id)

    def test_network_delete_start(self):
        payload = dict(network_id=fake_network.id)

        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.network_delete_start(payload)
            disable.assertCalledOnceWith(fake_network.id)

    def test_subnet_delete_start(self):
        payload = dict(subnet_id=fake_subnet1.id)
        self.cache.get_network_by_subnet_id.return_value = fake_network

        self.dhcp.subnet_delete_start(payload)

        self.cache.assert_has_calls(
            [mock.call.get_network_by_subnet_id(fake_subnet1.id)])

        self.plugin.assert_has_calls(
            [mock.call.release_port_fixed_ip(fake_network.id,
                                             mock.ANY,
                                             fake_subnet1.id)])
        self.assertEqual(self.call_driver.call_count, 0)

    def test_refresh_dhcp_helper_no_dhcp_enabled_networks(self):
        network = FakeModel('12345678-1234-5678-1234567890ab',
                            tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                            admin_state_up=True,
                            subnets=[],
                            ports=[])

        self.plugin.get_network_info.return_value = network
        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.refresh_dhcp_helper(network.id)
            disable.called_once_with_args(network.id)
            self.assertFalse(self.cache.called)
            self.assertFalse(self.call_driver.called)

    def test_subnet_update_end(self):
        payload = dict(subnet=dict(network_id=fake_network.id))
        self.cache.get_network_by_id.return_value = fake_network
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_update_end(payload)

        self.cache.assert_has_calls([mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('update_l3', fake_network)

    def test_subnet_update_end_delete_payload(self):
        payload = dict(subnet_id=fake_subnet1.id)
        self.cache.get_network_by_subnet_id.return_value = fake_network
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_delete_end(payload)

        self.cache.assert_has_calls([mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('update_l3', fake_network)

    def test_port_update_end(self):
        payload = dict(port=vars(fake_port2))
        self.cache.get_network_by_id.return_value = fake_network
        self.dhcp.port_update_end(payload)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_port2.network_id),
             mock.call.put_port(mock.ANY)])
        self.call_driver.assert_called_once_with('reload_allocations',
                                                 fake_network)

    def test_port_delete_end(self):
        payload = dict(port_id=fake_port2.id)
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port2

        self.dhcp.port_delete_end(payload)

        self.cache.assert_has_calls(
            [mock.call.get_port_by_id(fake_port2.id),
             mock.call.get_network_by_id(fake_network.id),
             mock.call.remove_port(fake_port2)])
        self.call_driver.assert_called_once_with('reload_allocations',
                                                 fake_network)

    def test_port_delete_end_unknown_port(self):
        payload = dict(port_id='unknown')
        self.cache.get_port_by_id.return_value = None

        self.dhcp.port_delete_end(payload)

        self.cache.assert_has_calls([mock.call.get_port_by_id('unknown')])
        self.assertEqual(self.call_driver.call_count, 0)


class TestDhcpPluginApiProxy(unittest.TestCase):
    def setUp(self):
        self.proxy = dhcp_agent.DhcpPluginApi('foo', {})
        self.proxy.host = 'foo'

        self.call_p = mock.patch.object(self.proxy, 'call')
        self.call = self.call_p.start()
        self.make_msg_p = mock.patch.object(self.proxy, 'make_msg')
        self.make_msg = self.make_msg_p.start()

    def tearDown(self):
        self.make_msg_p.stop()
        self.call_p.stop()

    def test_get_active_networks(self):
        self.proxy.get_active_networks()
        self.call.assert_called()
        self.make_msg.assert_called_once_with('get_active_networks',
                                              host='foo')

    def test_get_network_info(self):
        self.call.return_value = dict(a=1)
        retval = self.proxy.get_network_info('netid')
        self.assertEqual(retval.a, 1)
        self.call.assert_called()
        self.make_msg.assert_called_once_with('get_network_info',
                                              network_id='netid',
                                              host='foo')

    def test_get_dhcp_port(self):
        self.call.return_value = dict(a=1)
        retval = self.proxy.get_dhcp_port('netid', 'devid')
        self.assertEqual(retval.a, 1)
        self.call.assert_called()
        self.make_msg.assert_called_once_with('get_dhcp_port',
                                              network_id='netid',
                                              device_id='devid',
                                              host='foo')

    def test_release_dhcp_port(self):
        self.proxy.release_dhcp_port('netid', 'devid')
        self.call.assert_called()
        self.make_msg.assert_called_once_with('release_dhcp_port',
                                              network_id='netid',
                                              device_id='devid',
                                              host='foo')

    def test_release_port_fixed_ip(self):
        self.proxy.release_port_fixed_ip('netid', 'devid', 'subid')
        self.call.assert_called()
        self.make_msg.assert_called_once_with('release_port_fixed_ip',
                                              network_id='netid',
                                              subnet_id='subid',
                                              device_id='devid',
                                              host='foo')


class TestNetworkCache(unittest.TestCase):
    def test_put_network(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        self.assertEqual(nc.cache,
                         {fake_network.id: fake_network})
        self.assertEqual(nc.subnet_lookup,
                         {fake_subnet1.id: fake_network.id,
                          fake_subnet2.id: fake_network.id})
        self.assertEqual(nc.port_lookup,
                         {fake_port1.id: fake_network.id})

    def test_put_network_existing(self):
        prev_network_info = mock.Mock()
        nc = dhcp_agent.NetworkCache()
        with mock.patch.object(nc, 'remove') as remove:
            nc.cache[fake_network.id] = prev_network_info

            nc.put(fake_network)
            remove.assert_called_once_with(prev_network_info)
        self.assertEqual(nc.cache,
                         {fake_network.id: fake_network})
        self.assertEqual(nc.subnet_lookup,
                         {fake_subnet1.id: fake_network.id,
                          fake_subnet2.id: fake_network.id})
        self.assertEqual(nc.port_lookup,
                         {fake_port1.id: fake_network.id})

    def test_remove_network(self):
        nc = dhcp_agent.NetworkCache()
        nc.cache = {fake_network.id: fake_network}
        nc.subnet_lookup = {fake_subnet1.id: fake_network.id,
                            fake_subnet2.id: fake_network.id}
        nc.port_lookup = {fake_port1.id: fake_network.id}
        nc.remove(fake_network)

        self.assertEqual(len(nc.cache), 0)
        self.assertEqual(len(nc.subnet_lookup), 0)
        self.assertEqual(len(nc.port_lookup), 0)

    def test_get_network_by_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_id(fake_network.id), fake_network)

    def test_get_network_by_subnet_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_subnet_id(fake_subnet1.id),
                         fake_network)

    def test_get_network_by_port_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_port_id(fake_port1.id),
                         fake_network)

    def test_put_port(self):
        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                 subnets=[fake_subnet1],
                                 ports=[fake_port1])
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        nc.put_port(fake_port2)
        self.assertEqual(len(nc.port_lookup), 2)
        self.assertIn(fake_port2, fake_network.ports)

    def test_put_port_existing(self):
        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                 subnets=[fake_subnet1],
                                 ports=[fake_port1, fake_port2])
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        nc.put_port(fake_port2)

        self.assertEqual(len(nc.port_lookup), 2)
        self.assertIn(fake_port2, fake_network.ports)

    def test_remove_port_existing(self):
        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                 subnets=[fake_subnet1],
                                 ports=[fake_port1, fake_port2])

        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        nc.remove_port(fake_port2)

        self.assertEqual(len(nc.port_lookup), 1)
        self.assertNotIn(fake_port2, fake_network.ports)

    def test_get_port_by_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        self.assertEqual(nc.get_port_by_id(fake_port1.id), fake_port1)


class TestDeviceManager(unittest.TestCase):
    def setUp(self):
        cfg.CONF.register_opts(dhcp_agent.DeviceManager.OPTS)
        cfg.CONF.register_opts(dhcp_agent.DhcpAgent.OPTS)
        cfg.CONF.set_override('interface_driver',
                              'quantum.agent.linux.interface.NullDriver')
        cfg.CONF.root_helper = 'sudo'

        self.device_exists_p = mock.patch(
            'quantum.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.dvr_cls_p = mock.patch('quantum.agent.linux.interface.NullDriver')
        driver_cls = self.dvr_cls_p.start()
        self.mock_driver = mock.MagicMock()
        self.mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        driver_cls.return_value = self.mock_driver

    def tearDown(self):
        self.dvr_cls_p.stop()
        self.device_exists_p.stop()

    def _test_setup_helper(self, device_exists, reuse_existing=False):
        plugin = mock.Mock()
        plugin.get_dhcp_port.return_value = fake_port1
        self.device_exists.return_value = device_exists
        self.mock_driver.get_device_name.return_value = 'tap12345678-12'

        dh = dhcp_agent.DeviceManager(cfg.CONF, plugin)
        dh.setup(fake_network, reuse_existing)

        plugin.assert_has_calls([
            mock.call.get_dhcp_port(fake_network.id, mock.ANY)])

        expected = [mock.call.init_l3('tap12345678-12',
                                      ['172.9.9.9/24'],
                                      namespace=fake_network.id)]

        if not reuse_existing:
            expected.insert(0,
                            mock.call.plug(fake_network.id,
                                           fake_port1.id,
                                           'tap12345678-12',
                                           'aa:bb:cc:dd:ee:ff',
                                           namespace=fake_network.id))

        self.mock_driver.assert_has_calls(expected)

    def test_setup(self):
        self._test_setup_helper(False)

    def test_setup_device_exists(self):
        with self.assertRaises(exceptions.PreexistingDeviceFailure):
            self._test_setup_helper(True)

    def test_setup_device_exists_reuse(self):
        self._test_setup_helper(True, True)

    def test_destroy(self):
        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa')

        fake_port = FakeModel('12345678-1234-aaaa-1234567890ab',
                              mac_address='aa:bb:cc:dd:ee:ff')

        expected_driver_calls = [mock.call(cfg.CONF),
                                 mock.call().get_device_name(fake_network),
                                 mock.call().unplug('tap12345678-12')]

        with mock.patch('quantum.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            #mock_driver.DEV_NAME_LEN = (
            #    interface.LinuxInterfaceDriver.DEV_NAME_LEN)
            #mock_driver.port = fake_port
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()
            plugin.get_dhcp_port.return_value = fake_port

            dh = dhcp_agent.DeviceManager(cfg.CONF, plugin)
            dh.destroy(fake_network)

            dvr_cls.assert_called_once_with(cfg.CONF)
            mock_driver.assert_has_calls(
                [mock.call.get_device_name(mock.ANY),
                 mock.call.unplug('tap12345678-12',
                                  namespace=fake_network.id)])
            plugin.assert_has_calls(
                [mock.call.get_dhcp_port(fake_network.id, mock.ANY),
                 mock.call.release_dhcp_port(fake_network.id, mock.ANY)])

    def test_update_l3(self):
        fake_network = mock.Mock()

        dh = dhcp_agent.DeviceManager(cfg.CONF, None)
        with mock.patch.object(dh, 'setup') as setup:
            dh.update_l3(fake_network)
            setup.called_once_with(fake_network, True)

    def test_get_interface_name(self):
        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa')

        fake_port = FakeModel('12345678-1234-aaaa-1234567890ab',
                              mac_address='aa:bb:cc:dd:ee:ff')

        expected_driver_calls = [mock.call(cfg.CONF),
                                 mock.call().get_device_name(fake_network),
                                 mock.call().unplug('tap12345678-12')]

        with mock.patch('quantum.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()
            plugin.get_dhcp_port.return_value = fake_port

            dh = dhcp_agent.DeviceManager(cfg.CONF, plugin)
            dh.get_interface_name(fake_network, fake_port)

            dvr_cls.assert_called_once_with(cfg.CONF)
            mock_driver.assert_has_calls(
                [mock.call.get_device_name(fake_port)])

            self.assertEqual(len(plugin.mock_calls), 0)

    def test_get_interface_name_no_port_provided(self):
        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa')

        fake_port = FakeModel('12345678-1234-aaaa-1234567890ab',
                              mac_address='aa:bb:cc:dd:ee:ff')

        expected_driver_calls = [mock.call(cfg.CONF),
                                 mock.call().get_device_name(fake_network),
                                 mock.call().unplug('tap12345678-12')]

        with mock.patch('quantum.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()
            plugin.get_dhcp_port.return_value = fake_port

            dh = dhcp_agent.DeviceManager(cfg.CONF, plugin)
            dh.get_interface_name(fake_network)

            dvr_cls.assert_called_once_with(cfg.CONF)
            mock_driver.assert_has_calls(
                [mock.call.get_device_name(fake_port)])

            plugin.assert_has_calls(
                [mock.call.get_dhcp_port(fake_network.id, mock.ANY)])

    def test_get_device_id(self):
        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa')
        expected = ('dhcp1ae5f96c-c527-5079-82ea-371a01645457-12345678-1234-'
                    '5678-1234567890ab')

        with mock.patch('socket.gethostbyname') as get_host:
            with mock.patch('uuid.uuid5') as uuid5:
                uuid5.return_value = '1ae5f96c-c527-5079-82ea-371a01645457'
                get_host.return_value = 'localhost'

                dh = dhcp_agent.DeviceManager(cfg.CONF, None)
                uuid5.called_once_with(uuid.NAMESPACE_DNS, 'localhost')
                self.assertEqual(dh.get_device_id(fake_network), expected)


class TestDictModel(unittest.TestCase):
    def test_basic_dict(self):
        d = dict(a=1, b=2)

        m = dhcp_agent.DictModel(d)
        self.assertEqual(m.a, 1)
        self.assertEqual(m.b, 2)

    def test_dict_has_sub_dict(self):
        d = dict(a=dict(b=2))
        m = dhcp_agent.DictModel(d)
        self.assertEqual(m.a.b, 2)

    def test_dict_contains_list(self):
        d = dict(a=[1, 2])

        m = dhcp_agent.DictModel(d)
        self.assertEqual(m.a, [1, 2])

    def test_dict_contains_list_of_dicts(self):
        d = dict(a=[dict(b=2), dict(c=3)])

        m = dhcp_agent.DictModel(d)
        self.assertEqual(m.a[0].b, 2)
        self.assertEqual(m.a[1].c, 3)
