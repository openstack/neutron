# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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
#
# @author: Mark McClain, DreamHost

import contextlib

import mock

from neutron.services.loadbalancer.drivers.haproxy import (
    agent_manager as manager
)
from neutron.tests import base


class TestLogicalDeviceCache(base.BaseTestCase):
    def setUp(self):
        super(TestLogicalDeviceCache, self).setUp()
        self.cache = manager.LogicalDeviceCache()

    def test_put(self):
        fake_device = {
            'vip': {'port_id': 'port_id'},
            'pool': {'id': 'pool_id'}
        }
        self.cache.put(fake_device)

        self.assertEqual(len(self.cache.devices), 1)
        self.assertEqual(len(self.cache.port_lookup), 1)
        self.assertEqual(len(self.cache.pool_lookup), 1)

    def test_double_put(self):
        fake_device = {
            'vip': {'port_id': 'port_id'},
            'pool': {'id': 'pool_id'}
        }
        self.cache.put(fake_device)
        self.cache.put(fake_device)

        self.assertEqual(len(self.cache.devices), 1)
        self.assertEqual(len(self.cache.port_lookup), 1)
        self.assertEqual(len(self.cache.pool_lookup), 1)

    def test_remove_in_cache(self):
        fake_device = {
            'vip': {'port_id': 'port_id'},
            'pool': {'id': 'pool_id'}
        }
        self.cache.put(fake_device)

        self.assertEqual(len(self.cache.devices), 1)

        self.cache.remove(fake_device)

        self.assertFalse(len(self.cache.devices))
        self.assertFalse(self.cache.port_lookup)
        self.assertFalse(self.cache.pool_lookup)

    def test_remove_in_cache_same_object(self):
        fake_device = {
            'vip': {'port_id': 'port_id'},
            'pool': {'id': 'pool_id'}
        }
        self.cache.put(fake_device)

        self.assertEqual(len(self.cache.devices), 1)

        self.cache.remove(set(self.cache.devices).pop())

        self.assertFalse(len(self.cache.devices))
        self.assertFalse(self.cache.port_lookup)
        self.assertFalse(self.cache.pool_lookup)

    def test_remove_by_pool_id(self):
        fake_device = {
            'vip': {'port_id': 'port_id'},
            'pool': {'id': 'pool_id'}
        }
        self.cache.put(fake_device)

        self.assertEqual(len(self.cache.devices), 1)

        self.cache.remove_by_pool_id('pool_id')

        self.assertFalse(len(self.cache.devices))
        self.assertFalse(self.cache.port_lookup)
        self.assertFalse(self.cache.pool_lookup)

    def test_get_by_pool_id(self):
        fake_device = {
            'vip': {'port_id': 'port_id'},
            'pool': {'id': 'pool_id'}
        }
        self.cache.put(fake_device)

        dev = self.cache.get_by_pool_id('pool_id')

        self.assertEqual(dev.pool_id, 'pool_id')
        self.assertEqual(dev.port_id, 'port_id')

    def test_get_by_port_id(self):
        fake_device = {
            'vip': {'port_id': 'port_id'},
            'pool': {'id': 'pool_id'}
        }
        self.cache.put(fake_device)

        dev = self.cache.get_by_port_id('port_id')

        self.assertEqual(dev.pool_id, 'pool_id')
        self.assertEqual(dev.port_id, 'port_id')

    def test_get_pool_ids(self):
        fake_device = {
            'vip': {'port_id': 'port_id'},
            'pool': {'id': 'pool_id'}
        }
        self.cache.put(fake_device)

        self.assertEqual(self.cache.get_pool_ids(), ['pool_id'])


class TestManager(base.BaseTestCase):
    def setUp(self):
        super(TestManager, self).setUp()
        self.addCleanup(mock.patch.stopall)

        mock_conf = mock.Mock()
        mock_conf.interface_driver = 'intdriver'
        mock_conf.device_driver = 'devdriver'
        mock_conf.AGENT.root_helper = 'sudo'
        mock_conf.loadbalancer_state_path = '/the/path'

        self.mock_importer = mock.patch.object(manager, 'importutils').start()

        rpc_mock_cls = mock.patch(
            'neutron.services.loadbalancer.drivers'
            '.haproxy.agent_api.LbaasAgentApi'
        ).start()

        # disable setting up periodic state reporting
        mock_conf.AGENT.report_interval = 0

        self.mgr = manager.LbaasAgentManager(mock_conf)
        self.rpc_mock = rpc_mock_cls.return_value
        self.log = mock.patch.object(manager, 'LOG').start()
        self.mgr.needs_resync = False

    def test_initialize_service_hook(self):
        with mock.patch.object(self.mgr, 'sync_state') as sync:
            self.mgr.initialize_service_hook(mock.Mock())
            sync.assert_called_once_with()

    def test_periodic_resync_needs_sync(self):
        with mock.patch.object(self.mgr, 'sync_state') as sync:
            self.mgr.needs_resync = True
            self.mgr.periodic_resync(mock.Mock())
            sync.assert_called_once_with()

    def test_periodic_resync_no_sync(self):
        with mock.patch.object(self.mgr, 'sync_state') as sync:
            self.mgr.needs_resync = False
            self.mgr.periodic_resync(mock.Mock())
            self.assertFalse(sync.called)

    def test_collect_stats(self):
        with mock.patch.object(self.mgr, 'cache') as cache:
            cache.get_pool_ids.return_value = ['1', '2']
            self.mgr.collect_stats(mock.Mock())
            self.rpc_mock.update_pool_stats.assert_has_calls([
                mock.call('1', mock.ANY),
                mock.call('2', mock.ANY)
            ])

    def test_collect_stats_exception(self):
        with mock.patch.object(self.mgr, 'cache') as cache:
            cache.get_pool_ids.return_value = ['1', '2']
            with mock.patch.object(self.mgr, 'driver') as driver:
                driver.get_stats.side_effect = Exception

                self.mgr.collect_stats(mock.Mock())

                self.assertFalse(self.rpc_mock.called)
                self.assertTrue(self.mgr.needs_resync)
                self.assertTrue(self.log.exception.called)

    def test_vip_plug_callback(self):
        self.mgr._vip_plug_callback('plug', {'id': 'id'})
        self.rpc_mock.plug_vip_port.assert_called_once_with('id')

    def test_vip_unplug_callback(self):
        self.mgr._vip_plug_callback('unplug', {'id': 'id'})
        self.rpc_mock.unplug_vip_port.assert_called_once_with('id')

    def _sync_state_helper(self, cache, ready, refreshed, destroyed):
        with contextlib.nested(
            mock.patch.object(self.mgr, 'cache'),
            mock.patch.object(self.mgr, 'refresh_device'),
            mock.patch.object(self.mgr, 'destroy_device')
        ) as (mock_cache, refresh, destroy):

            mock_cache.get_pool_ids.return_value = cache
            self.rpc_mock.get_ready_devices.return_value = ready

            self.mgr.sync_state()

            self.assertEqual(len(refreshed), len(refresh.mock_calls))
            self.assertEqual(len(destroyed), len(destroy.mock_calls))

            refresh.assert_has_calls([mock.call(i) for i in refreshed])
            destroy.assert_has_calls([mock.call(i) for i in destroyed])
            self.assertFalse(self.mgr.needs_resync)

    def test_sync_state_all_known(self):
        self._sync_state_helper(['1', '2'], ['1', '2'], ['1', '2'], [])

    def test_sync_state_all_unknown(self):
        self._sync_state_helper([], ['1', '2'], ['1', '2'], [])

    def test_sync_state_destroy_all(self):
        self._sync_state_helper(['1', '2'], [], [], ['1', '2'])

    def test_sync_state_both(self):
        self._sync_state_helper(['1'], ['2'], ['2'], ['1'])

    def test_sync_state_exception(self):
        self.rpc_mock.get_ready_devices.side_effect = Exception

        self.mgr.sync_state()

        self.assertTrue(self.log.exception.called)
        self.assertTrue(self.mgr.needs_resync)

    def test_refresh_device_exists(self):
        config = self.rpc_mock.get_logical_device.return_value

        with mock.patch.object(self.mgr, 'driver') as driver:
            with mock.patch.object(self.mgr, 'cache') as cache:
                driver.exists.return_value = True

                self.mgr.refresh_device(config)

                driver.exists.assert_called_once_with(config)
                driver.update.assert_called_once_with(config)
                cache.put.assert_called_once_with(config)
                self.assertFalse(self.mgr.needs_resync)

    def test_refresh_device_new(self):
        config = self.rpc_mock.get_logical_device.return_value

        with mock.patch.object(self.mgr, 'driver') as driver:
            with mock.patch.object(self.mgr, 'cache') as cache:
                driver.exists.return_value = False

                self.mgr.refresh_device(config)

                driver.exists.assert_called_once_with(config)
                driver.create.assert_called_once_with(config)
                cache.put.assert_called_once_with(config)
                self.assertFalse(self.mgr.needs_resync)

    def test_refresh_device_exception(self):
        config = self.rpc_mock.get_logical_device.return_value

        with mock.patch.object(self.mgr, 'driver') as driver:
            with mock.patch.object(self.mgr, 'cache') as cache:
                driver.exists.side_effect = Exception
                self.mgr.refresh_device(config)

                driver.exists.assert_called_once_with(config)
                self.assertTrue(self.mgr.needs_resync)
                self.assertTrue(self.log.exception.called)
                self.assertFalse(cache.put.called)

    def test_destroy_device_known(self):
        with mock.patch.object(self.mgr, 'driver') as driver:
            with mock.patch.object(self.mgr, 'cache') as cache:
                cache.get_by_pool_id.return_value = True

                self.mgr.destroy_device('pool_id')
                cache.get_by_pool_id.assert_called_once_with('pool_id')
                driver.destroy.assert_called_once_with('pool_id')
                self.rpc_mock.pool_destroyed.assert_called_once_with(
                    'pool_id'
                )
                cache.remove.assert_called_once_with(True)
                self.assertFalse(self.mgr.needs_resync)

    def test_destroy_device_unknown(self):
        with mock.patch.object(self.mgr, 'driver') as driver:
            with mock.patch.object(self.mgr, 'cache') as cache:
                cache.get_by_pool_id.return_value = None

                self.mgr.destroy_device('pool_id')
                cache.get_by_pool_id.assert_called_once_with('pool_id')
                self.assertFalse(driver.destroy.called)

    def test_destroy_device_exception(self):
        with mock.patch.object(self.mgr, 'driver') as driver:
            with mock.patch.object(self.mgr, 'cache') as cache:
                cache.get_by_pool_id.return_value = True
                driver.destroy.side_effect = Exception

                self.mgr.destroy_device('pool_id')
                cache.get_by_pool_id.assert_called_once_with('pool_id')

                self.assertTrue(self.log.exception.called)
                self.assertTrue(self.mgr.needs_resync)

    def test_remove_orphans(self):
        with mock.patch.object(self.mgr, 'driver') as driver:
            with mock.patch.object(self.mgr, 'cache') as cache:
                cache.get_pool_ids.return_value = ['1', '2']
                self.mgr.remove_orphans()

                driver.remove_orphans.assert_called_once_with(['1', '2'])

    def test_reload_pool(self):
        with mock.patch.object(self.mgr, 'refresh_device') as refresh:
            self.mgr.reload_pool(mock.Mock(), pool_id='pool_id')
            refresh.assert_called_once_with('pool_id')

    def test_modify_pool_known(self):
        with mock.patch.object(self.mgr, 'refresh_device') as refresh:
            with mock.patch.object(self.mgr, 'cache') as cache:
                cache.get_by_pool_id.return_value = True

                self.mgr.reload_pool(mock.Mock(), pool_id='pool_id')

                refresh.assert_called_once_with('pool_id')

    def test_modify_pool_unknown(self):
        with mock.patch.object(self.mgr, 'refresh_device') as refresh:
            with mock.patch.object(self.mgr, 'cache') as cache:
                cache.get_by_pool_id.return_value = False

                self.mgr.modify_pool(mock.Mock(), pool_id='pool_id')

                self.assertFalse(refresh.called)

    def test_destroy_pool_known(self):
        with mock.patch.object(self.mgr, 'destroy_device') as destroy:
            with mock.patch.object(self.mgr, 'cache') as cache:
                cache.get_by_pool_id.return_value = True

                self.mgr.destroy_pool(mock.Mock(), pool_id='pool_id')

                destroy.assert_called_once_with('pool_id')

    def test_destroy_pool_unknown(self):
        with mock.patch.object(self.mgr, 'destroy_device') as destroy:
            with mock.patch.object(self.mgr, 'cache') as cache:
                cache.get_by_pool_id.return_value = False

                self.mgr.destroy_pool(mock.Mock(), pool_id='pool_id')

                self.assertFalse(destroy.called)
