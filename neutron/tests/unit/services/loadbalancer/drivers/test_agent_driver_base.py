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

import contextlib

import mock
from six import moves
from webob import exc

from neutron import context
from neutron.db.loadbalancer import loadbalancer_db as ldb
from neutron.db import servicetype_db as st_db
from neutron.extensions import loadbalancer
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers.common import agent_driver_base
from neutron.tests import base
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer
from neutron.tests.unit import testlib_api


class TestLoadBalancerPluginBase(
    test_db_loadbalancer.LoadBalancerPluginDbTestCase):

    def setUp(self):
        def reset_device_driver():
            agent_driver_base.AgentDriverBase.device_driver = None
        self.addCleanup(reset_device_driver)

        self.mock_importer = mock.patch.object(
            agent_driver_base, 'importutils').start()

        # needed to reload provider configuration
        st_db.ServiceTypeManager._instance = None
        agent_driver_base.AgentDriverBase.device_driver = 'dummy'
        super(TestLoadBalancerPluginBase, self).setUp(
            lbaas_provider=('LOADBALANCER:lbaas:neutron.services.'
                            'loadbalancer.drivers.common.agent_driver_base.'
                            'AgentDriverBase:default'))

        # we need access to loaded plugins to modify models
        loaded_plugins = manager.NeutronManager().get_service_plugins()

        self.plugin_instance = loaded_plugins[constants.LOADBALANCER]


class TestLoadBalancerCallbacks(TestLoadBalancerPluginBase):
    def setUp(self):
        super(TestLoadBalancerCallbacks, self).setUp()

        self.callbacks = agent_driver_base.LoadBalancerCallbacks(
            self.plugin_instance
        )
        get_lbaas_agents_patcher = mock.patch(
            'neutron.services.loadbalancer.agent_scheduler'
            '.LbaasAgentSchedulerDbMixin.get_lbaas_agents')
        get_lbaas_agents_patcher.start()

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
        for i in moves.xrange(3):
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
            self.assertEqual(len(ready), 3)
            self.assertIn(pools[0].id, ready)
            self.assertIn(pools[1].id, ready)
            self.assertIn(pools[2].id, ready)
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
                self.assertEqual([vip['vip']['pool_id']], ready)

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

    def test_get_logical_device_non_active(self):
        with self.pool() as pool:
            ctx = context.get_admin_context()
            for status in ('INACTIVE', 'PENDING_CREATE', 'PENDING_UPDATE'):
                self.plugin_instance.update_status(
                    ctx, ldb.Pool, pool['pool']['id'], status)
                pool['pool']['status'] = status
                expected = {
                    'pool': pool['pool'],
                    'members': [],
                    'healthmonitors': [],
                    'driver': 'dummy'
                }

                logical_config = self.callbacks.get_logical_device(
                    ctx, pool['pool']['id']
                )

                self.assertEqual(expected, logical_config)

    def test_get_logical_device_active(self):
        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                with self.member(pool_id=vip['vip']['pool_id']) as member:
                    ctx = context.get_admin_context()
                    # activate objects
                    self.plugin_instance.update_status(
                        ctx, ldb.Pool, pool['pool']['id'], 'ACTIVE')
                    self.plugin_instance.update_status(
                        ctx, ldb.Member, member['member']['id'], 'ACTIVE')
                    self.plugin_instance.update_status(
                        ctx, ldb.Vip, vip['vip']['id'], 'ACTIVE')

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
                        'healthmonitors': [],
                        'driver': 'dummy'
                    }

                    logical_config = self.callbacks.get_logical_device(
                        ctx, pool['id']
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
                        ctx, pool['pool']['id'])

                    member['member']['status'] = constants.INACTIVE
                    self.assertEqual([member['member']],
                                     logical_config['members'])

    def test_get_logical_device_pending_create_member(self):
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

                    member = self.plugin_instance.get_member(
                        ctx, member['member']['id'])
                    self.assertEqual('PENDING_CREATE',
                                     member['status'])
                    logical_config = self.callbacks.get_logical_device(
                        ctx, pool['pool']['id'])

                    self.assertEqual([member], logical_config['members'])

    def test_get_logical_device_pending_create_health_monitor(self):
        with self.health_monitor() as monitor:
            with self.pool() as pool:
                with self.vip(pool=pool) as vip:
                    ctx = context.get_admin_context()
                    self.plugin_instance.update_status(ctx, ldb.Pool,
                                                       pool['pool']['id'],
                                                       'ACTIVE')
                    self.plugin_instance.update_status(ctx, ldb.Vip,
                                                       vip['vip']['id'],
                                                       'ACTIVE')
                    self.plugin_instance.create_pool_health_monitor(
                        ctx, monitor, pool['pool']['id'])
                    pool = self.plugin_instance.get_pool(
                        ctx, pool['pool']['id'])
                    monitor = self.plugin_instance.get_health_monitor(
                        ctx, monitor['health_monitor']['id'])

                    self.assertEqual(
                        'PENDING_CREATE',
                        pool['health_monitors_status'][0]['status'])
                    logical_config = self.callbacks.get_logical_device(
                        ctx, pool['id'])

                    self.assertEqual([monitor],
                                     logical_config['healthmonitors'])

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

    def test_pool_deployed(self):
        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                with self.member(pool_id=vip['vip']['pool_id']) as member:
                    ctx = context.get_admin_context()
                    p = self.plugin_instance.get_pool(ctx, pool['pool']['id'])
                    self.assertEqual('PENDING_CREATE', p['status'])
                    v = self.plugin_instance.get_vip(ctx, vip['vip']['id'])
                    self.assertEqual('PENDING_CREATE', v['status'])
                    m = self.plugin_instance.get_member(
                        ctx, member['member']['id'])
                    self.assertEqual('PENDING_CREATE', m['status'])

                    self.callbacks.pool_deployed(ctx, pool['pool']['id'])

                    p = self.plugin_instance.get_pool(ctx, pool['pool']['id'])
                    self.assertEqual('ACTIVE', p['status'])
                    v = self.plugin_instance.get_vip(ctx, vip['vip']['id'])
                    self.assertEqual('ACTIVE', v['status'])
                    m = self.plugin_instance.get_member(
                        ctx, member['member']['id'])
                    self.assertEqual('ACTIVE', m['status'])

    def test_update_status_pool(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            ctx = context.get_admin_context()
            p = self.plugin_instance.get_pool(ctx, pool_id)
            self.assertEqual('PENDING_CREATE', p['status'])
            self.callbacks.update_status(ctx, 'pool', pool_id, 'ACTIVE')
            p = self.plugin_instance.get_pool(ctx, pool_id)
            self.assertEqual('ACTIVE', p['status'])

    def test_update_status_pool_deleted_already(self):
        with mock.patch.object(agent_driver_base, 'LOG') as mock_log:
            pool_id = 'deleted_pool'
            ctx = context.get_admin_context()
            self.assertRaises(loadbalancer.PoolNotFound,
                              self.plugin_instance.get_pool, ctx, pool_id)
            self.callbacks.update_status(ctx, 'pool', pool_id, 'ACTIVE')
            self.assertTrue(mock_log.warning.called)

    def test_update_status_health_monitor(self):
        with contextlib.nested(
            self.health_monitor(),
            self.pool()
        ) as (hm, pool):
            pool_id = pool['pool']['id']
            ctx = context.get_admin_context()
            self.plugin_instance.create_pool_health_monitor(ctx, hm, pool_id)
            hm_id = hm['health_monitor']['id']
            h = self.plugin_instance.get_pool_health_monitor(ctx, hm_id,
                                                             pool_id)
            self.assertEqual('PENDING_CREATE', h['status'])
            self.callbacks.update_status(
                ctx, 'health_monitor',
                {'monitor_id': hm_id, 'pool_id': pool_id}, 'ACTIVE')
            h = self.plugin_instance.get_pool_health_monitor(ctx, hm_id,
                                                             pool_id)
            self.assertEqual('ACTIVE', h['status'])


class TestLoadBalancerAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestLoadBalancerAgentApi, self).setUp()

        self.api = agent_driver_base.LoadBalancerAgentApi('topic')
        self.mock_cast = mock.patch.object(self.api, 'cast').start()
        self.mock_msg = mock.patch.object(self.api, 'make_msg').start()

    def test_init(self):
        self.assertEqual(self.api.topic, 'topic')

    def _call_test_helper(self, method_name, method_args):
        rv = getattr(self.api, method_name)(mock.sentinel.context,
                                            host='host',
                                            **method_args)
        self.assertEqual(rv, self.mock_cast.return_value)
        self.mock_cast.assert_called_once_with(
            mock.sentinel.context,
            self.mock_msg.return_value,
            topic='topic.host',
            version=None
        )

        if method_name == 'agent_updated':
            method_args = {'payload': method_args}
        self.mock_msg.assert_called_once_with(
            method_name,
            **method_args
        )

    def test_agent_updated(self):
        self._call_test_helper('agent_updated', {'admin_state_up': 'test'})

    def test_create_pool(self):
        self._call_test_helper('create_pool', {'pool': 'test',
                                               'driver_name': 'dummy'})

    def test_update_pool(self):
        self._call_test_helper('update_pool', {'old_pool': 'test',
                                               'pool': 'test'})

    def test_delete_pool(self):
        self._call_test_helper('delete_pool', {'pool': 'test'})

    def test_create_vip(self):
        self._call_test_helper('create_vip', {'vip': 'test'})

    def test_update_vip(self):
        self._call_test_helper('update_vip', {'old_vip': 'test',
                                              'vip': 'test'})

    def test_delete_vip(self):
        self._call_test_helper('delete_vip', {'vip': 'test'})

    def test_create_member(self):
        self._call_test_helper('create_member', {'member': 'test'})

    def test_update_member(self):
        self._call_test_helper('update_member', {'old_member': 'test',
                                                 'member': 'test'})

    def test_delete_member(self):
        self._call_test_helper('delete_member', {'member': 'test'})

    def test_create_monitor(self):
        self._call_test_helper('create_pool_health_monitor',
                               {'health_monitor': 'test', 'pool_id': 'test'})

    def test_update_monitor(self):
        self._call_test_helper('update_pool_health_monitor',
                               {'old_health_monitor': 'test',
                                'health_monitor': 'test',
                                'pool_id': 'test'})

    def test_delete_monitor(self):
        self._call_test_helper('delete_pool_health_monitor',
                               {'health_monitor': 'test', 'pool_id': 'test'})


class TestLoadBalancerPluginNotificationWrapper(TestLoadBalancerPluginBase):
    def setUp(self):
        self.log = mock.patch.object(agent_driver_base, 'LOG')
        api_cls = mock.patch.object(agent_driver_base,
                                    'LoadBalancerAgentApi').start()
        super(TestLoadBalancerPluginNotificationWrapper, self).setUp()
        self.mock_api = api_cls.return_value

        self.mock_get_driver = mock.patch.object(self.plugin_instance,
                                                 '_get_driver')
        self.mock_get_driver.return_value = (agent_driver_base.
                                             AgentDriverBase(
                                                 self.plugin_instance
                                             ))

    def test_create_vip(self):
        with self.subnet() as subnet:
            with self.pool(subnet=subnet) as pool:
                with self.vip(pool=pool, subnet=subnet) as vip:
                    self.mock_api.create_vip.assert_called_once_with(
                        mock.ANY,
                        vip['vip'],
                        'host'
                    )

    def test_update_vip(self):
        with self.subnet() as subnet:
            with self.pool(subnet=subnet) as pool:
                with self.vip(pool=pool, subnet=subnet) as vip:
                    ctx = context.get_admin_context()
                    old_vip = vip['vip'].copy()
                    vip['vip'].pop('status')
                    new_vip = self.plugin_instance.update_vip(
                        ctx,
                        vip['vip']['id'],
                        vip
                    )

                    self.mock_api.update_vip.assert_called_once_with(
                        mock.ANY,
                        old_vip,
                        new_vip,
                        'host'
                    )

                    self.assertEqual(
                        new_vip['status'],
                        constants.PENDING_UPDATE
                    )

    def test_delete_vip(self):
        with self.subnet() as subnet:
            with self.pool(subnet=subnet) as pool:
                with self.vip(pool=pool, subnet=subnet,
                              do_delete=False) as vip:
                    ctx = context.get_admin_context()
                    self.plugin_instance.delete_vip(ctx, vip['vip']['id'])
                    vip['vip']['status'] = 'PENDING_DELETE'
                    self.mock_api.delete_vip.assert_called_once_with(
                        mock.ANY,
                        vip['vip'],
                        'host'
                    )

    def test_create_pool(self):
        with self.pool() as pool:
            self.mock_api.create_pool.assert_called_once_with(
                mock.ANY,
                pool['pool'],
                mock.ANY,
                'dummy'
            )

    def test_update_pool_non_active(self):
        with self.pool() as pool:
            pool['pool']['status'] = 'INACTIVE'
            ctx = context.get_admin_context()
            orig_pool = pool['pool'].copy()
            del pool['pool']['provider']
            self.plugin_instance.update_pool(ctx, pool['pool']['id'], pool)
            self.mock_api.delete_pool.assert_called_once_with(
                mock.ANY, orig_pool, 'host')

    def test_update_pool_no_vip_id(self):
        with self.pool() as pool:
            ctx = context.get_admin_context()
            orig_pool = pool['pool'].copy()
            del pool['pool']['provider']
            updated = self.plugin_instance.update_pool(
                ctx, pool['pool']['id'], pool)
            self.mock_api.update_pool.assert_called_once_with(
                mock.ANY, orig_pool, updated, 'host')

    def test_update_pool_with_vip_id(self):
        with self.pool() as pool:
            with self.vip(pool=pool) as vip:
                ctx = context.get_admin_context()
                old_pool = pool['pool'].copy()
                old_pool['vip_id'] = vip['vip']['id']
                del pool['pool']['provider']
                updated = self.plugin_instance.update_pool(
                    ctx, pool['pool']['id'], pool)
                self.mock_api.update_pool.assert_called_once_with(
                    mock.ANY, old_pool, updated, 'host')

    def test_delete_pool(self):
        with self.pool(do_delete=False) as pool:
            req = self.new_delete_request('pools',
                                          pool['pool']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, exc.HTTPNoContent.code)
            pool['pool']['status'] = 'PENDING_DELETE'
            self.mock_api.delete_pool.assert_called_once_with(
                mock.ANY, pool['pool'], 'host')

    def test_create_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id) as member:
                self.mock_api.create_member.assert_called_once_with(
                    mock.ANY, member['member'], 'host')

    def test_update_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id) as member:
                ctx = context.get_admin_context()
                updated = self.plugin_instance.update_member(
                    ctx, member['member']['id'], member)
                self.mock_api.update_member.assert_called_once_with(
                    mock.ANY, member['member'], updated, 'host')

    def test_update_member_new_pool(self):
        with self.pool() as pool1:
            pool1_id = pool1['pool']['id']
            with self.pool() as pool2:
                pool2_id = pool2['pool']['id']
                with self.member(pool_id=pool1_id) as member:
                    self.mock_api.create_member.reset_mock()
                    ctx = context.get_admin_context()
                    old_member = member['member'].copy()
                    member['member']['pool_id'] = pool2_id
                    updated = self.plugin_instance.update_member(
                        ctx, member['member']['id'], member)
                    self.mock_api.delete_member.assert_called_once_with(
                        mock.ANY, old_member, 'host')
                    self.mock_api.create_member.assert_called_once_with(
                        mock.ANY, updated, 'host')

    def test_delete_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id,
                             do_delete=False) as member:
                req = self.new_delete_request('members',
                                              member['member']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
                member['member']['status'] = 'PENDING_DELETE'
                self.mock_api.delete_member.assert_called_once_with(
                    mock.ANY, member['member'], 'host')

    def test_create_pool_health_monitor(self):
        with contextlib.nested(
            self.health_monitor(),
            self.pool(),
        ) as (hm, pool):
            pool_id = pool['pool']['id']
            ctx = context.get_admin_context()
            self.plugin_instance.create_pool_health_monitor(ctx, hm, pool_id)
            # hm now has a ref to the pool with which it is associated
            hm = self.plugin.get_health_monitor(
                ctx, hm['health_monitor']['id'])
            self.mock_api.create_pool_health_monitor.assert_called_once_with(
                mock.ANY, hm, pool_id, 'host')

    def test_delete_pool_health_monitor(self):
        with contextlib.nested(
            self.pool(),
            self.health_monitor()
        ) as (pool, hm):
            pool_id = pool['pool']['id']
            ctx = context.get_admin_context()
            self.plugin_instance.create_pool_health_monitor(ctx, hm, pool_id)
            # hm now has a ref to the pool with which it is associated
            hm = self.plugin.get_health_monitor(
                ctx, hm['health_monitor']['id'])
            hm['pools'][0]['status'] = 'PENDING_DELETE'
            self.plugin_instance.delete_pool_health_monitor(
                ctx, hm['id'], pool_id)
            self.mock_api.delete_pool_health_monitor.assert_called_once_with(
                mock.ANY, hm, pool_id, 'host')

    def test_update_health_monitor_associated_with_pool(self):
        with contextlib.nested(
            self.health_monitor(type='HTTP'),
            self.pool()
        ) as (monitor, pool):
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
            # hm now has a ref to the pool with which it is associated
            ctx = context.get_admin_context()
            hm = self.plugin.get_health_monitor(
                ctx, monitor['health_monitor']['id'])
            self.mock_api.create_pool_health_monitor.assert_called_once_with(
                mock.ANY,
                hm,
                pool['pool']['id'],
                'host'
            )

            self.mock_api.reset_mock()
            data = {'health_monitor': {'delay': 20,
                                       'timeout': 20,
                                       'max_retries': 2,
                                       'admin_state_up': False}}
            updated = hm.copy()
            updated.update(data['health_monitor'])
            req = self.new_update_request("health_monitors",
                                          data,
                                          monitor['health_monitor']['id'])
            req.get_response(self.ext_api)
            self.mock_api.update_pool_health_monitor.assert_called_once_with(
                mock.ANY,
                hm,
                updated,
                pool['pool']['id'],
                'host')
