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

import mock
from webob import exc

from neutron.common import exceptions
from neutron import context
from neutron.db.loadbalancer import loadbalancer_db as ldb
from neutron.db import servicetype_db as st_db
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers.haproxy import (
    plugin_driver
)
from neutron.tests import base
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer
from neutron.tests.unit import testlib_api


class TestLoadBalancerPluginBase(
    test_db_loadbalancer.LoadBalancerPluginDbTestCase):

    def setUp(self):
        # needed to reload provider configuration
        st_db.ServiceTypeManager._instance = None
        super(TestLoadBalancerPluginBase, self).setUp(
            lbaas_provider=('LOADBALANCER:lbaas:neutron.services.'
                            'loadbalancer.drivers.haproxy.plugin_driver.'
                            'HaproxyOnHostPluginDriver:default'))
        # create another API instance to make testing easier
        # pass a mock to our API instance

        # we need access to loaded plugins to modify models
        loaded_plugins = manager.NeutronManager().get_service_plugins()

        self.plugin_instance = loaded_plugins[constants.LOADBALANCER]


class TestLoadBalancerCallbacks(TestLoadBalancerPluginBase):
    def setUp(self):
        super(TestLoadBalancerCallbacks, self).setUp()

        self.callbacks = plugin_driver.LoadBalancerCallbacks(
            self.plugin_instance
        )
        get_lbaas_agents_patcher = mock.patch(
            'neutron.services.loadbalancer.agent_scheduler'
            '.LbaasAgentSchedulerDbMixin.get_lbaas_agents')
        get_lbaas_agents_patcher.start()

        # mocking plugin_driver create_pool() as it does nothing more than
        # pool scheduling which is beyond the scope of this test case
        mock.patch('neutron.services.loadbalancer.drivers.haproxy'
                   '.plugin_driver.HaproxyOnHostPluginDriver'
                   '.create_pool').start()

        self.addCleanup(mock.patch.stopall)

    def test_get_ready_devices(self):
        with self.vip() as vip:
            with mock.patch('neutron.services.loadbalancer.agent_scheduler'
                            '.LbaasAgentSchedulerDbMixin.'
                            'list_pools_on_lbaas_agent') as mock_agent_pools:
                mock_agent_pools.return_value = {
                    'pools': [{'id': vip['vip']['pool_id']}]}
                ready = self.callbacks.get_ready_devices(
                    context.get_admin_context(),
                )
                self.assertEqual(ready, [vip['vip']['pool_id']])

    def test_get_ready_devices_multiple_vips_and_pools(self):
        ctx = context.get_admin_context()

        # add 3 pools and 2 vips directly to DB
        # to create 2 "ready" devices and one pool without vip
        pools = []
        for i in xrange(0, 3):
            pools.append(ldb.Pool(id=uuidutils.generate_uuid(),
                                  subnet_id=self._subnet_id,
                                  protocol="HTTP",
                                  lb_method="ROUND_ROBIN",
                                  status=constants.ACTIVE,
                                  admin_state_up=True))
            ctx.session.add(pools[i])

        vip0 = ldb.Vip(id=uuidutils.generate_uuid(),
                       protocol_port=80,
                       protocol="HTTP",
                       pool_id=pools[0].id,
                       status=constants.ACTIVE,
                       admin_state_up=True,
                       connection_limit=3)
        ctx.session.add(vip0)
        pools[0].vip_id = vip0.id

        vip1 = ldb.Vip(id=uuidutils.generate_uuid(),
                       protocol_port=80,
                       protocol="HTTP",
                       pool_id=pools[1].id,
                       status=constants.ACTIVE,
                       admin_state_up=True,
                       connection_limit=3)
        ctx.session.add(vip1)
        pools[1].vip_id = vip1.id

        ctx.session.flush()

        self.assertEqual(ctx.session.query(ldb.Pool).count(), 3)
        self.assertEqual(ctx.session.query(ldb.Vip).count(), 2)
        with mock.patch('neutron.services.loadbalancer.agent_scheduler'
                        '.LbaasAgentSchedulerDbMixin'
                        '.list_pools_on_lbaas_agent') as mock_agent_pools:
            mock_agent_pools.return_value = {'pools': [{'id': pools[0].id},
                                                       {'id': pools[1].id},
                                                       {'id': pools[2].id}]}
            ready = self.callbacks.get_ready_devices(ctx)
            self.assertEqual(len(ready), 2)
            self.assertIn(pools[0].id, ready)
            self.assertIn(pools[1].id, ready)
            self.assertNotIn(pools[2].id, ready)
        # cleanup
        ctx.session.query(ldb.Pool).delete()
        ctx.session.query(ldb.Vip).delete()

    def test_get_ready_devices_inactive_vip(self):
        with self.vip() as vip:

            # set the vip inactive need to use plugin directly since
            # status is not tenant mutable
            self.plugin_instance.update_vip(
                context.get_admin_context(),
                vip['vip']['id'],
                {'vip': {'status': constants.INACTIVE}}
            )
            with mock.patch('neutron.services.loadbalancer.agent_scheduler'
                            '.LbaasAgentSchedulerDbMixin.'
                            'list_pools_on_lbaas_agent') as mock_agent_pools:
                mock_agent_pools.return_value = {
                    'pools': [{'id': vip['vip']['pool_id']}]}
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
            with mock.patch('neutron.services.loadbalancer.agent_scheduler'
                            '.LbaasAgentSchedulerDbMixin.'
                            'list_pools_on_lbaas_agent') as mock_agent_pools:
                mock_agent_pools.return_value = {
                    'pools': [{'id': vip['vip']['pool_id']}]}
                ready = self.callbacks.get_ready_devices(
                    context.get_admin_context(),
                )
                self.assertFalse(ready)

    def test_get_logical_device_inactive(self):
        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                with self.member(pool_id=vip['vip']['pool_id']):
                    self.assertRaises(
                        exceptions.Invalid,
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

    def test_get_logical_device_inactive_member(self):
        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                with self.member(pool_id=vip['vip']['pool_id']) as member:
                    ctx = context.get_admin_context()
                    self.plugin_instance.update_status(ctx, ldb.Pool,
                                                       pool['pool']['id'],
                                                       'ACTIVE')
                    self.plugin_instance.update_status(ctx, ldb.Vip,
                                                       vip['vip']['id'],
                                                       'ACTIVE')
                    self.plugin_instance.update_status(ctx, ldb.Member,
                                                       member['member']['id'],
                                                       'INACTIVE')

                    logical_config = self.callbacks.get_logical_device(
                        ctx, pool['pool']['id'], activate=False)

                    member['member']['status'] = constants.INACTIVE
                    self.assertEqual([member['member']],
                                     logical_config['members'])

    def _update_port_test_helper(self, expected, func, **kwargs):
        core = self.plugin_instance._core_plugin

        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                with self.member(pool_id=vip['vip']['pool_id']):
                    ctx = context.get_admin_context()
                    func(ctx, port_id=vip['vip']['port_id'], **kwargs)

                    db_port = core.get_port(ctx, vip['vip']['port_id'])

                    for k, v in expected.iteritems():
                        self.assertEqual(db_port[k], v)

    def test_plug_vip_port(self):
        exp = {
            'device_owner': 'neutron:' + constants.LOADBALANCER,
            'device_id': 'c596ce11-db30-5c72-8243-15acaae8690f',
            'admin_state_up': True
        }
        self._update_port_test_helper(
            exp,
            self.callbacks.plug_vip_port,
            host='host'
        )

    def test_plug_vip_port_mock_with_host(self):
        exp = {
            'device_owner': 'neutron:' + constants.LOADBALANCER,
            'device_id': 'c596ce11-db30-5c72-8243-15acaae8690f',
            'admin_state_up': True,
            portbindings.HOST_ID: 'host'
        }
        with mock.patch.object(
            self.plugin._core_plugin, 'update_port') as mock_update_port:
            with self.pool() as pool:
                with self.vip(pool=pool) as vip:
                    ctx = context.get_admin_context()
                    self.callbacks.plug_vip_port(
                        ctx, port_id=vip['vip']['port_id'], host='host')
            mock_update_port.assert_called_once_with(
                ctx, vip['vip']['port_id'],
                {'port': testlib_api.SubDictMatch(exp)})

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

        self.api = plugin_driver.LoadBalancerAgentApi('topic')
        self.mock_cast = mock.patch.object(self.api, 'cast').start()
        self.mock_msg = mock.patch.object(self.api, 'make_msg').start()

    def test_init(self):
        self.assertEqual(self.api.topic, 'topic')

    def _call_test_helper(self, method_name):
        rv = getattr(self.api, method_name)(mock.sentinel.context, 'test',
                                            'host')
        self.assertEqual(rv, self.mock_cast.return_value)
        self.mock_cast.assert_called_once_with(
            mock.sentinel.context,
            self.mock_msg.return_value,
            topic='topic.host'
        )

        self.mock_msg.assert_called_once_with(
            method_name,
            pool_id='test',
            host='host'
        )

    def test_reload_pool(self):
        self._call_test_helper('reload_pool')

    def test_destroy_pool(self):
        self._call_test_helper('destroy_pool')

    def test_modify_pool(self):
        self._call_test_helper('modify_pool')

    def test_agent_updated(self):
        rv = self.api.agent_updated(mock.sentinel.context, True, 'host')
        self.assertEqual(rv, self.mock_cast.return_value)
        self.mock_cast.assert_called_once_with(
            mock.sentinel.context,
            self.mock_msg.return_value,
            topic='topic.host',
            version='1.1'
        )

        self.mock_msg.assert_called_once_with(
            'agent_updated',
            payload={'admin_state_up': True}
        )


class TestLoadBalancerPluginNotificationWrapper(TestLoadBalancerPluginBase):
    def setUp(self):
        self.log = mock.patch.object(plugin_driver, 'LOG')
        api_cls = mock.patch.object(plugin_driver,
                                    'LoadBalancerAgentApi').start()
        super(TestLoadBalancerPluginNotificationWrapper, self).setUp()
        self.mock_api = api_cls.return_value

        # mocking plugin_driver create_pool() as it does nothing more than
        # pool scheduling which is beyond the scope of this test case
        mock.patch('neutron.services.loadbalancer.drivers.haproxy'
                   '.plugin_driver.HaproxyOnHostPluginDriver'
                   '.create_pool').start()

        self.mock_get_driver = mock.patch.object(self.plugin_instance,
                                                 '_get_driver')
        self.mock_get_driver.return_value = (plugin_driver.
                                             HaproxyOnHostPluginDriver(
                                                 self.plugin_instance
                                             ))

        self.addCleanup(mock.patch.stopall)

    def test_create_vip(self):
        with self.subnet() as subnet:
            with self.pool(subnet=subnet) as pool:
                with self.vip(pool=pool, subnet=subnet) as vip:
                    self.mock_api.reload_pool.assert_called_once_with(
                        mock.ANY,
                        vip['vip']['pool_id'],
                        'host'
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
                        vip['vip']['pool_id'],
                        'host'
                    )

                    self.assertEqual(
                        new_vip['status'],
                        constants.PENDING_UPDATE
                    )

    def test_delete_vip(self):
        with self.subnet() as subnet:
            with self.pool(subnet=subnet) as pool:
                with self.vip(pool=pool, subnet=subnet, no_delete=True) as vip:
                    self.mock_api.reset_mock()
                    ctx = context.get_admin_context()
                    self.plugin_instance.delete_vip(ctx, vip['vip']['id'])
                    self.mock_api.destroy_pool.assert_called_once_with(
                        mock.ANY,
                        vip['vip']['pool_id'],
                        'host'
                    )

    def test_create_pool(self):
        with self.pool():
            self.assertFalse(self.mock_api.reload_pool.called)
            self.assertFalse(self.mock_api.modify_pool.called)
            self.assertFalse(self.mock_api.destroy_pool.called)

    def test_update_pool_non_active(self):
        with self.pool() as pool:
            pool['pool']['status'] = 'INACTIVE'
            ctx = context.get_admin_context()
            del pool['pool']['provider']
            self.plugin_instance.update_pool(ctx, pool['pool']['id'], pool)
            self.mock_api.destroy_pool.assert_called_once_with(
                mock.ANY, pool['pool']['id'], 'host')
            self.assertFalse(self.mock_api.reload_pool.called)
            self.assertFalse(self.mock_api.modify_pool.called)

    def test_update_pool_no_vip_id(self):
        with self.pool() as pool:
            ctx = context.get_admin_context()
            del pool['pool']['provider']
            self.plugin_instance.update_pool(ctx, pool['pool']['id'], pool)
            self.assertFalse(self.mock_api.destroy_pool.called)
            self.assertFalse(self.mock_api.reload_pool.called)
            self.assertFalse(self.mock_api.modify_pool.called)

    def test_update_pool_with_vip_id(self):
        with self.pool() as pool:
            with self.vip(pool=pool):
                ctx = context.get_admin_context()
                del pool['pool']['provider']
                self.plugin_instance.update_pool(ctx, pool['pool']['id'], pool)
                self.mock_api.reload_pool.assert_called_once_with(
                    mock.ANY, pool['pool']['id'], 'host')
                self.assertFalse(self.mock_api.destroy_pool.called)
                self.assertFalse(self.mock_api.modify_pool.called)

    def test_delete_pool(self):
        with self.pool(no_delete=True) as pool:
            req = self.new_delete_request('pools',
                                          pool['pool']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, exc.HTTPNoContent.code)
            self.mock_api.destroy_pool.assert_called_once_with(
                mock.ANY, pool['pool']['id'], 'host')

    def test_create_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id):
                self.mock_api.modify_pool.assert_called_once_with(
                    mock.ANY, pool_id, 'host')

    def test_update_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id) as member:
                ctx = context.get_admin_context()
                self.mock_api.modify_pool.reset_mock()
                self.plugin_instance.update_member(
                    ctx, member['member']['id'], member)
                self.mock_api.modify_pool.assert_called_once_with(
                    mock.ANY, pool_id, 'host')

    def test_update_member_new_pool(self):
        with self.pool() as pool1:
            pool1_id = pool1['pool']['id']
            with self.pool() as pool2:
                pool2_id = pool2['pool']['id']
                with self.member(pool_id=pool1_id) as member:
                    ctx = context.get_admin_context()
                    self.mock_api.modify_pool.reset_mock()
                    member['member']['pool_id'] = pool2_id
                    self.plugin_instance.update_member(ctx,
                                                       member['member']['id'],
                                                       member)
                    self.assertEqual(2, self.mock_api.modify_pool.call_count)
                    self.mock_api.modify_pool.assert_has_calls(
                        [mock.call(mock.ANY, pool1_id, 'host'),
                         mock.call(mock.ANY, pool2_id, 'host')])

    def test_delete_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id,
                             no_delete=True) as member:
                self.mock_api.modify_pool.reset_mock()
                req = self.new_delete_request('members',
                                              member['member']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
                self.mock_api.modify_pool.assert_called_once_with(
                    mock.ANY, pool_id, 'host')

    def test_create_pool_health_monitor(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.health_monitor() as hm:
                ctx = context.get_admin_context()
                self.plugin_instance.create_pool_health_monitor(ctx,
                                                                hm,
                                                                pool_id)
                self.mock_api.modify_pool.assert_called_once_with(
                    mock.ANY, pool_id, 'host')

    def test_delete_pool_health_monitor(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.health_monitor() as hm:
                ctx = context.get_admin_context()
                self.plugin_instance.create_pool_health_monitor(ctx,
                                                                hm,
                                                                pool_id)
                self.mock_api.modify_pool.reset_mock()
                self.plugin_instance.delete_pool_health_monitor(
                    ctx, hm['health_monitor']['id'], pool_id)
                self.mock_api.modify_pool.assert_called_once_with(
                    mock.ANY, pool_id, 'host')

    def test_update_health_monitor_associated_with_pool(self):
        with self.health_monitor(type='HTTP') as monitor:
            with self.pool() as pool:
                data = {
                    'health_monitor': {
                        'id': monitor['health_monitor']['id'],
                        'tenant_id': self._tenant_id
                    }
                }
                req = self.new_create_request(
                    'pools',
                    data,
                    fmt=self.fmt,
                    id=pool['pool']['id'],
                    subresource='health_monitors')
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPCreated.code)
                self.mock_api.modify_pool.assert_called_once_with(
                    mock.ANY,
                    pool['pool']['id'],
                    'host'
                )

                self.mock_api.reset_mock()
                data = {'health_monitor': {'delay': 20,
                                           'timeout': 20,
                                           'max_retries': 2,
                                           'admin_state_up': False}}
                req = self.new_update_request("health_monitors",
                                              data,
                                              monitor['health_monitor']['id'])
                req.get_response(self.ext_api)
                self.mock_api.modify_pool.assert_called_once_with(
                    mock.ANY,
                    pool['pool']['id'],
                    'host'
                )
