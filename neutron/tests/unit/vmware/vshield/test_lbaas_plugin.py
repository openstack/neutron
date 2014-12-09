# Copyright 2013 VMware, Inc
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

import contextlib

import testtools
from webob import exc as web_exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.extensions import loadbalancer as lb
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer
from neutron.tests.unit.vmware.vshield import test_edge_router

_uuid = uuidutils.generate_uuid

LBAAS_PLUGIN_CLASS = "neutron.plugins.vmware.plugin.NsxServicePlugin"


class LoadBalancerTestExtensionManager(
        test_edge_router.ServiceRouterTestExtensionManager):

    def get_resources(self):
        # If l3 resources have been loaded and updated by main API
        # router, update the map in the l3 extension so it will load
        # the same attributes as the API router
        resources = super(LoadBalancerTestExtensionManager,
                          self).get_resources()
        lb_attr_map = lb.RESOURCE_ATTRIBUTE_MAP.copy()
        for res in lb.RESOURCE_ATTRIBUTE_MAP.keys():
            attr_info = attributes.RESOURCE_ATTRIBUTE_MAP.get(res)
            if attr_info:
                lb.RESOURCE_ATTRIBUTE_MAP[res] = attr_info
        lb_resources = lb.Loadbalancer.get_resources()
        # restore the original resources once the controllers are created
        lb.RESOURCE_ATTRIBUTE_MAP = lb_attr_map
        resources.extend(lb_resources)
        return resources


class TestLoadbalancerPlugin(
    test_db_loadbalancer.LoadBalancerPluginDbTestCase,
    test_edge_router.ServiceRouterTest):

    def vcns_loadbalancer_patch(self):
        instance = self.vcns_instance
        instance.return_value.create_vip.side_effect = (
            self.fc2.create_vip)
        instance.return_value.get_vip.side_effect = (
            self.fc2.get_vip)
        instance.return_value.update_vip.side_effect = (
            self.fc2.update_vip)
        instance.return_value.delete_vip.side_effect = (
            self.fc2.delete_vip)
        instance.return_value.create_pool.side_effect = (
            self.fc2.create_pool)
        instance.return_value.get_pool.side_effect = (
            self.fc2.get_pool)
        instance.return_value.update_pool.side_effect = (
            self.fc2.update_pool)
        instance.return_value.delete_pool.side_effect = (
            self.fc2.delete_pool)
        instance.return_value.create_health_monitor.side_effect = (
            self.fc2.create_health_monitor)
        instance.return_value.get_health_monitor.side_effect = (
            self.fc2.get_health_monitor)
        instance.return_value.update_health_monitor.side_effect = (
            self.fc2.update_health_monitor)
        instance.return_value.delete_health_monitor.side_effect = (
            self.fc2.delete_health_monitor)
        instance.return_value.create_app_profile.side_effect = (
            self.fc2.create_app_profile)
        instance.return_value.update_app_profile.side_effect = (
            self.fc2.update_app_profile)
        instance.return_value.delete_app_profile.side_effect = (
            self.fc2.delete_app_profile)

    def setUp(self):
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()

        super(TestLoadbalancerPlugin, self).setUp(
            ext_mgr=LoadBalancerTestExtensionManager(),
            lb_plugin=LBAAS_PLUGIN_CLASS)
        self.vcns_loadbalancer_patch()
        self.plugin = manager.NeutronManager.get_plugin()

    def tearDown(self):
        super(TestLoadbalancerPlugin, self).tearDown()
        # Restore the global RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map
        self.ext_api = None
        self.plugin = None

    def _create_and_get_router(self):
        req = self._create_router(self.fmt, self._tenant_id)
        res = self.deserialize(self.fmt, req)
        return res['router']['id']

    def _get_vip_optional_args(self):
        args = super(TestLoadbalancerPlugin, self)._get_vip_optional_args()
        return args + ('router_id',)

    def test_update_healthmonitor(self):
        keys = [('type', "TCP"),
                ('tenant_id', self._tenant_id),
                ('delay', 20),
                ('timeout', 20),
                ('max_retries', 2),
                ('admin_state_up', False)]

        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, health_mon, pool):
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            with self.vip(
                router_id=self._create_and_get_router(),
                pool=pool, subnet=subnet):
                    self.plugin.create_pool_health_monitor(
                        context.get_admin_context(),
                        health_mon, pool['pool']['id']
                    )
                    data = {'health_monitor': {'delay': 20,
                                               'timeout': 20,
                                               'max_retries': 2,
                                               'admin_state_up': False}}
                    req = self.new_update_request(
                        "health_monitors",
                        data,
                        health_mon['health_monitor']['id'])
                    res = self.deserialize(
                        self.fmt, req.get_response(self.ext_api))
                    for k, v in keys:
                        self.assertEqual(res['health_monitor'][k], v)

    def test_create_vip(self, **extras):
        expected = {
            'name': 'vip1',
            'description': '',
            'protocol_port': 80,
            'protocol': 'HTTP',
            'connection_limit': -1,
            'admin_state_up': True,
            'status': 'ACTIVE',
            'router_id': self._create_and_get_router(),
            'tenant_id': self._tenant_id,
        }

        expected.update(extras)

        name = expected['name']

        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, monitor, pool):
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            expected['pool_id'] = pool['pool']['id']
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool['pool']['id']
            )
            with self.vip(
                router_id=expected['router_id'], name=name,
                pool=pool, subnet=subnet, **extras) as vip:
                for k in ('id', 'address', 'port_id', 'pool_id'):
                    self.assertTrue(vip['vip'].get(k, None))
                self.assertEqual(
                    dict((k, v)
                         for k, v in vip['vip'].items() if k in expected),
                    expected
                )

    def test_create_vip_with_session_persistence(self):
        self.test_create_vip(session_persistence={'type': 'HTTP_COOKIE'})

    def test_create_vip_with_invalid_persistence_method(self):
        with testtools.ExpectedException(web_exc.HTTPClientError):
            self.test_create_vip(
                protocol='TCP',
                session_persistence={'type': 'HTTP_COOKIE'})

    def test_create_vips_with_same_names(self):
        new_router_id = self._create_and_get_router()
        with self.subnet() as subnet:
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            with contextlib.nested(
                self.vip(
                    name='vip',
                    router_id=new_router_id,
                    subnet=subnet, protocol_port=80),
                self.vip(
                    name='vip',
                    router_id=new_router_id,
                    subnet=subnet, protocol_port=81),
                self.vip(
                    name='vip',
                    router_id=new_router_id,
                    subnet=subnet, protocol_port=82),
            ) as (vip1, vip2, vip3):
                req = self.new_list_request('vips')
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api))
                for index in range(len(res['vips'])):
                    self.assertEqual(res['vips'][index]['name'], 'vip')

    def test_update_vip(self):
        name = 'new_vip'
        router_id = self._create_and_get_router()
        keys = [('router_id', router_id),
                ('name', name),
                ('address', "10.0.0.2"),
                ('protocol_port', 80),
                ('connection_limit', 100),
                ('admin_state_up', False),
                ('status', 'ACTIVE')]

        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, monitor, pool):
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool['pool']['id']
            )
            with self.vip(
                router_id=router_id, name=name,
                pool=pool, subnet=subnet) as vip:
                keys.append(('subnet_id', vip['vip']['subnet_id']))
                data = {'vip': {'name': name,
                                'connection_limit': 100,
                                'session_persistence':
                                {'type': "APP_COOKIE",
                                 'cookie_name': "jesssionId"},
                                'admin_state_up': False}}
                req = self.new_update_request(
                    'vips', data, vip['vip']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['vip'][k], v)

    def test_delete_vip(self):
        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, monitor, pool):
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool['pool']['id']
            )
            with self.vip(
                router_id=self._create_and_get_router(),
                pool=pool, subnet=subnet, do_delete=False) as vip:
                req = self.new_delete_request('vips', vip['vip']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)

    def test_delete_router_in_use_by_lbservice(self):
        router_id = self._create_and_get_router()
        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, monitor, pool):
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool['pool']['id']
            )
            with self.vip(
                router_id=router_id,
                pool=pool, subnet=subnet):
                self._delete('routers', router_id,
                             expected_code=web_exc.HTTPConflict.code)

    def test_show_vip(self):
        router_id = self._create_and_get_router()
        name = "vip_show"
        keys = [('name', name),
                ('protocol_port', 80),
                ('protocol', 'HTTP'),
                ('connection_limit', -1),
                ('admin_state_up', True),
                ('status', 'ACTIVE'),
                ('router_id', router_id)]

        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, monitor, pool):
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool['pool']['id']
            )
            with self.vip(
                router_id=router_id, name=name,
                pool=pool, subnet=subnet) as vip:
                req = self.new_show_request('vips',
                                            vip['vip']['id'])
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['vip'][k], v)

    def test_list_vips(self):
        keys_list = []
        for i in range(3):
            keys_list.append({'name': "vip" + str(i),
                              'router_id': self._create_and_get_router(),
                              'protocol_port': 80 + i,
                              'protocol': "HTTP",
                              'status': "ACTIVE",
                              'admin_state_up': True})

        with self.subnet() as subnet:
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            with contextlib.nested(
                self.vip(
                    router_id=keys_list[0]['router_id'], name='vip0',
                    subnet=subnet, protocol_port=80),
                self.vip(
                    router_id=keys_list[1]['router_id'], name='vip1',
                    subnet=subnet, protocol_port=81),
                self.vip(
                    router_id=keys_list[2]['router_id'], name='vip2',
                    subnet=subnet, protocol_port=82),
            ) as (vip1, vip2, vip3):
                self._test_list_with_sort(
                    'vip',
                    (vip1, vip2, vip3),
                    [('protocol_port', 'asc'), ('name', 'desc')]
                )
                req = self.new_list_request('vips')
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api))
                self.assertEqual(len(res['vips']), 3)
                for index in range(len(res['vips'])):
                    for k, v in keys_list[index].items():
                        self.assertEqual(res['vips'][index][k], v)

    def test_update_pool(self):
        data = {'pool': {'name': "new_pool",
                         'admin_state_up': False}}
        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, monitor, pool):
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool['pool']['id']
            )
            with self.vip(
                router_id=self._create_and_get_router(),
                pool=pool, subnet=subnet):
                req = self.new_update_request(
                    'pools', data, pool['pool']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in data['pool'].items():
                    self.assertEqual(res['pool'][k], v)

    def test_create_member(self):
        router_id = self._create_and_get_router()
        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, monitor, pool):
            pool_id = pool['pool']['id']
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool['pool']['id']
            )
            with self.vip(
                router_id=router_id,
                pool=pool, subnet=subnet):
                with contextlib.nested(
                    self.member(address='192.168.1.100',
                                protocol_port=80,
                                pool_id=pool_id),
                    self.member(router_id=router_id,
                                address='192.168.1.101',
                                protocol_port=80,
                                pool_id=pool_id)) as (member1, member2):
                        req = self.new_show_request('pools',
                                                    pool_id,
                                                    fmt=self.fmt)
                        pool_update = self.deserialize(
                            self.fmt,
                            req.get_response(self.ext_api)
                        )
                        self.assertIn(member1['member']['id'],
                                      pool_update['pool']['members'])
                        self.assertIn(member2['member']['id'],
                                      pool_update['pool']['members'])

    def _show_pool(self, pool_id):
        req = self.new_show_request('pools', pool_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(web_exc.HTTPOk.code, res.status_int)
        return self.deserialize(self.fmt, res)

    def test_update_member(self):
        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool(name="pool1"),
            self.pool(name="pool2")
        ) as (subnet, monitor, pool1, pool2):
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool1['pool']['id']
            )
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool2['pool']['id']
            )
            with self.vip(
                router_id=self._create_and_get_router(),
                pool=pool1, subnet=subnet):
                keys = [('address', "192.168.1.100"),
                        ('tenant_id', self._tenant_id),
                        ('protocol_port', 80),
                        ('weight', 10),
                        ('pool_id', pool2['pool']['id']),
                        ('admin_state_up', False),
                        ('status', 'ACTIVE')]
                with self.member(
                    pool_id=pool1['pool']['id']) as member:

                    pool1_update = self._show_pool(pool1['pool']['id'])
                    self.assertEqual(len(pool1_update['pool']['members']), 1)
                    pool2_update = self._show_pool(pool2['pool']['id'])
                    self.assertEqual(len(pool1_update['pool']['members']), 1)
                    self.assertFalse(pool2_update['pool']['members'])

                    data = {'member': {'pool_id': pool2['pool']['id'],
                                       'weight': 10,
                                       'admin_state_up': False}}
                    req = self.new_update_request('members',
                                                  data,
                                                  member['member']['id'])
                    raw_res = req.get_response(self.ext_api)
                    self.assertEqual(web_exc.HTTPOk.code, raw_res.status_int)
                    res = self.deserialize(self.fmt, raw_res)
                    for k, v in keys:
                        self.assertEqual(res['member'][k], v)
                    pool1_update = self._show_pool(pool1['pool']['id'])
                    pool2_update = self._show_pool(pool2['pool']['id'])
                    self.assertEqual(len(pool2_update['pool']['members']), 1)
                    self.assertFalse(pool1_update['pool']['members'])

    def test_delete_member(self):
        with contextlib.nested(
            self.subnet(),
            self.health_monitor(),
            self.pool()
        ) as (subnet, monitor, pool):
            pool_id = pool['pool']['id']
            net_id = subnet['subnet']['network_id']
            self._set_net_external(net_id)
            self.plugin.create_pool_health_monitor(
                context.get_admin_context(),
                monitor, pool['pool']['id']
            )
            with self.vip(
                router_id=self._create_and_get_router(),
                pool=pool, subnet=subnet):
                with self.member(pool_id=pool_id,
                                 do_delete=False) as member:
                    req = self.new_delete_request('members',
                                                  member['member']['id'])
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 204)
                    pool_update = self._show_pool(pool['pool']['id'])
                    self.assertFalse(pool_update['pool']['members'])
