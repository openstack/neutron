# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC.
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
#
# @author: Mark McClain, DreamHost

import mock

from quantum import context
from quantum import manager
from quantum.plugins.common import constants
from quantum.plugins.services.agent_loadbalancer import plugin
from quantum.tests import base
from quantum.tests.unit.db.loadbalancer import test_db_loadbalancer


class TestLoadBalancerPluginBase(
    test_db_loadbalancer.LoadBalancerPluginDbTestCase):

    def setUp(self):
        super(TestLoadBalancerPluginBase, self).setUp()

        # create another API instance to make testing easier
        # pass a mock to our API instance

        # we need access to loaded plugins to modify models
        loaded_plugins = manager.QuantumManager().get_service_plugins()
        self.plugin_instance = loaded_plugins[constants.LOADBALANCER]
        self.callbacks = self.plugin_instance.callbacks


class TestLoadBalancerCallbacks(TestLoadBalancerPluginBase):
    def test_get_ready_devices(self):
        with self.vip() as vip:
            ready = self.callbacks.get_ready_devices(
                context.get_admin_context(),
            )
            self.assertEqual(ready, [vip['vip']['pool_id']])

    def test_get_ready_devices_inactive_vip(self):
        with self.vip() as vip:

            # set the vip inactive need to use plugin directly since
            # status is not tenant mutable
            self.plugin_instance.update_vip(
                context.get_admin_context(),
                vip['vip']['id'],
                {'vip': {'status': constants.INACTIVE}}
            )

            ready = self.callbacks.get_ready_devices(
                context.get_admin_context(),
            )
            self.assertFalse(ready)

    def test_get_ready_devices_inactive_pool(self):
        with self.vip() as vip:

            # set the pool inactive need to use plugin directly since
            # status is not tenant mutable
            self.plugin_instance.update_pool(
                context.get_admin_context(),
                vip['vip']['pool_id'],
                {'pool': {'status': constants.INACTIVE}}
            )

            ready = self.callbacks.get_ready_devices(
                context.get_admin_context(),
            )
            self.assertFalse(ready)

    def test_get_logical_device_inactive(self):
        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                with self.member(pool_id=vip['vip']['pool_id']) as member:
                    self.assertRaises(
                        Exception,
                        self.callbacks.get_logical_device,
                        context.get_admin_context(),
                        pool['pool']['id'],
                        activate=False
                    )

    def test_get_logical_device_activate(self):
        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                with self.member(pool_id=vip['vip']['pool_id']) as member:
                    ctx = context.get_admin_context()

                    # build the expected
                    port = self.plugin_instance._core_plugin.get_port(
                        ctx, vip['vip']['port_id']
                    )
                    subnet = self.plugin_instance._core_plugin.get_subnet(
                        ctx, vip['vip']['subnet_id']
                    )
                    port['fixed_ips'][0]['subnet'] = subnet

                    # reload pool to add members and vip
                    pool = self.plugin_instance.get_pool(
                        ctx, pool['pool']['id']
                    )

                    pool['status'] = constants.ACTIVE
                    vip['vip']['status'] = constants.ACTIVE
                    vip['vip']['port'] = port
                    member['member']['status'] = constants.ACTIVE

                    expected = {
                        'pool': pool,
                        'vip': vip['vip'],
                        'members': [member['member']],
                        'healthmonitors': []
                    }

                    logical_config = self.callbacks.get_logical_device(
                        ctx, pool['id'], activate=True
                    )

                    self.assertEqual(logical_config, expected)

    def _update_port_test_helper(self, expected, func, **kwargs):
        core = self.plugin_instance._core_plugin

        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                with self.member(pool_id=vip['vip']['pool_id']) as member:
                    ctx = context.get_admin_context()
                    func(ctx, port_id=vip['vip']['port_id'], **kwargs)

                    db_port = core.get_port(ctx, vip['vip']['port_id'])

                    for k, v in expected.iteritems():
                        self.assertEqual(db_port[k], v)

    def test_plug_vip_port(self):
        exp = {
            'device_owner': 'quantum:' + constants.LOADBALANCER,
            'device_id': 'c596ce11-db30-5c72-8243-15acaae8690f',
            'admin_state_up': True
        }
        self._update_port_test_helper(
            exp,
            self.callbacks.plug_vip_port,
            host='host'
        )

    def test_unplug_vip_port(self):
        exp = {
            'device_owner': '',
            'device_id': '',
            'admin_state_up': False
        }
        self._update_port_test_helper(
            exp,
            self.callbacks.unplug_vip_port,
            host='host'
        )


class TestLoadBalancerAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestLoadBalancerAgentApi, self).setUp()
        self.addCleanup(mock.patch.stopall)

        self.api = plugin.LoadBalancerAgentApi('topic', 'host')
        self.mock_cast = mock.patch.object(self.api, 'cast').start()
        self.mock_msg = mock.patch.object(self.api, 'make_msg').start()

    def test_init(self):
        self.assertEqual(self.api.topic, 'topic')
        self.assertEqual(self.api.host, 'host')

    def _call_test_helper(self, method_name):
        rv = getattr(self.api, method_name)(mock.sentinel.context, 'the_id')
        self.assertEqual(rv, self.mock_cast.return_value)
        self.mock_cast.assert_called_once_with(
            mock.sentinel.context,
            self.mock_msg.return_value,
            topic='topic'
        )

        self.mock_msg.assert_called_once_with(
            method_name,
            pool_id='the_id',
            host='host'
        )

    def test_reload_pool(self):
        self._call_test_helper('reload_pool')

    def test_destroy_pool(self):
        self._call_test_helper('destroy_pool')

    def test_modify_pool(self):
        self._call_test_helper('modify_pool')


class TestLoadBalancerPluginNotificationWrapper(TestLoadBalancerPluginBase):
    def setUp(self):
        self.log = mock.patch.object(plugin, 'LOG')
        api_cls = mock.patch.object(plugin, 'LoadBalancerAgentApi').start()
        super(TestLoadBalancerPluginNotificationWrapper, self).setUp()
        self.mock_api = api_cls.return_value

        self.addCleanup(mock.patch.stopall)

    def test_create_vip(self):
        with self.subnet() as subnet:
            with self.pool(subnet=subnet) as pool:
                with self.vip(pool=pool, subnet=subnet) as vip:
                    self.mock_api.reload_pool.assert_called_once_with(
                        mock.ANY,
                        vip['vip']['pool_id']
                    )

    def test_update_vip(self):
        with self.subnet() as subnet:
            with self.pool(subnet=subnet) as pool:
                with self.vip(pool=pool, subnet=subnet) as vip:
                    self.mock_api.reset_mock()
                    ctx = context.get_admin_context()
                    vip['vip'].pop('status')
                    new_vip = self.plugin_instance.update_vip(
                        ctx,
                        vip['vip']['id'],
                        vip
                    )

                    self.mock_api.reload_pool.assert_called_once_with(
                        mock.ANY,
                        vip['vip']['pool_id']
                    )

                    self.assertEqual(
                        new_vip['status'],
                        constants.PENDING_UPDATE
                    )

    def t2est_delete_vip(self):
        with self.subnet() as subnet:
            with self.pool(subnet=subnet) as pool:
                with self.vip(pool=pool, subnet=subnet, no_delete=True) as vip:
                    self.mock_api.reset_mock()
                    ctx = context.get_admin_context()
                    self.plugin_instance.delete_vip(context, vip['vip']['id'])
                    self.mock_api.destroy_pool.assert_called_once_with(
                        mock.ANY,
                        vip['vip']['pool_id']
                    )
