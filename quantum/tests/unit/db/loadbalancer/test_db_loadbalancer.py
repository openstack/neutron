# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import logging
import os
import testtools

import webob.exc

from quantum import context
from quantum.api.extensions import ExtensionMiddleware
from quantum.api.extensions import PluginAwareExtensionManager
from quantum.common import config
from quantum.db.loadbalancer import loadbalancer_db as ldb
import quantum.extensions
from quantum.extensions import loadbalancer
from quantum.plugins.common import constants
from quantum.plugins.services.agent_loadbalancer import (
    plugin as loadbalancer_plugin
)
from quantum.tests.unit import test_db_plugin


LOG = logging.getLogger(__name__)

DB_CORE_PLUGIN_KLASS = 'quantum.db.db_base_plugin_v2.QuantumDbPluginV2'
DB_LB_PLUGIN_KLASS = (
    "quantum.plugins.services.agent_loadbalancer.plugin.LoadBalancerPlugin"
)
ROOTDIR = os.path.dirname(__file__) + '../../../..'
ETCDIR = os.path.join(ROOTDIR, 'etc')

extensions_path = ':'.join(quantum.extensions.__path__)


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class LoadBalancerPluginDbTestCase(test_db_plugin.QuantumDbPluginV2TestCase):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.LOADBALANCER])
        for k in loadbalancer.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def setUp(self, core_plugin=None, lb_plugin=None):
        service_plugins = {'lb_plugin_name': DB_LB_PLUGIN_KLASS}

        super(LoadBalancerPluginDbTestCase, self).setUp(
            service_plugins=service_plugins
        )

        self._subnet_id = "0c798ed8-33ba-11e2-8b28-000c291c4d14"

        self.plugin = loadbalancer_plugin.LoadBalancerPlugin()
        ext_mgr = PluginAwareExtensionManager(
            extensions_path,
            {constants.LOADBALANCER: self.plugin}
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = ExtensionMiddleware(app, ext_mgr=ext_mgr)

    def _create_vip(self, fmt, name, pool_id, protocol, protocol_port,
                    admin_state_up, expected_res_status=None, **kwargs):
        data = {'vip': {'name': name,
                        'pool_id': pool_id,
                        'protocol': protocol,
                        'protocol_port': protocol_port,
                        'admin_state_up': admin_state_up,
                        'tenant_id': self._tenant_id}}
        for arg in ('description', 'subnet_id', 'address',
                    'session_persistence', 'connection_limit'):
            if arg in kwargs and kwargs[arg] is not None:
                data['vip'][arg] = kwargs[arg]

        vip_req = self.new_create_request('vips', data, fmt)
        vip_res = vip_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(vip_res.status_int, expected_res_status)

        return vip_res

    def _create_pool(self, fmt, name, lb_method, protocol, admin_state_up,
                     expected_res_status=None, **kwargs):
        data = {'pool': {'name': name,
                         'subnet_id': self._subnet_id,
                         'lb_method': lb_method,
                         'protocol': protocol,
                         'admin_state_up': admin_state_up,
                         'tenant_id': self._tenant_id}}
        for arg in ('description'):
            if arg in kwargs and kwargs[arg] is not None:
                data['pool'][arg] = kwargs[arg]

        pool_req = self.new_create_request('pools', data, fmt)
        pool_res = pool_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(pool_res.status_int, expected_res_status)

        return pool_res

    def _create_member(self, fmt, address, protocol_port, admin_state_up,
                       expected_res_status=None, **kwargs):
        data = {'member': {'address': address,
                           'protocol_port': protocol_port,
                           'admin_state_up': admin_state_up,
                           'tenant_id': self._tenant_id}}
        for arg in ('weight', 'pool_id'):
            if arg in kwargs and kwargs[arg] is not None:
                data['member'][arg] = kwargs[arg]

        member_req = self.new_create_request('members', data, fmt)
        member_res = member_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(member_res.status_int, expected_res_status)

        return member_res

    def _create_health_monitor(self, fmt, type, delay, timeout, max_retries,
                               admin_state_up, expected_res_status=None,
                               **kwargs):
        data = {'health_monitor': {'type': type,
                                   'delay': delay,
                                   'timeout': timeout,
                                   'max_retries': max_retries,
                                   'admin_state_up': admin_state_up,
                                   'tenant_id': self._tenant_id}}
        for arg in ('http_method', 'path', 'expected_code'):
            if arg in kwargs and kwargs[arg] is not None:
                data['health_monitor'][arg] = kwargs[arg]

        req = self.new_create_request('health_monitors', data, fmt)

        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(res.status_int, expected_res_status)

        return res

    def _api_for_resource(self, resource):
        if resource in ['networks', 'subnets', 'ports']:
            return self.api
        else:
            return self.ext_api

    @contextlib.contextmanager
    def vip(self, fmt=None, name='vip1', pool=None, subnet=None,
            protocol='HTTP', protocol_port=80, admin_state_up=True,
            no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        with test_db_plugin.optional_ctx(subnet, self.subnet) as tmp_subnet:
            with test_db_plugin.optional_ctx(pool, self.pool) as tmp_pool:
                pool_id = tmp_pool['pool']['id']
                res = self._create_vip(fmt,
                                       name,
                                       pool_id,
                                       protocol,
                                       protocol_port,
                                       admin_state_up,
                                       subnet_id=tmp_subnet['subnet']['id'],
                                       **kwargs)
                vip = self.deserialize(fmt or self.fmt, res)
                if res.status_int >= 400:
                    raise webob.exc.HTTPClientError(code=res.status_int)
                try:
                    yield vip
                finally:
                    if not no_delete:
                        self._delete('vips', vip['vip']['id'])

    @contextlib.contextmanager
    def pool(self, fmt=None, name='pool1', lb_method='ROUND_ROBIN',
             protocol='HTTP', admin_state_up=True, no_delete=False,
             **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_pool(fmt,
                                name,
                                lb_method,
                                protocol,
                                admin_state_up,
                                **kwargs)
        pool = self.deserialize(fmt or self.fmt, res)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        try:
            yield pool
        finally:
            if not no_delete:
                self._delete('pools', pool['pool']['id'])

    @contextlib.contextmanager
    def member(self, fmt=None, address='192.168.1.100', protocol_port=80,
               admin_state_up=True, no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_member(fmt,
                                  address,
                                  protocol_port,
                                  admin_state_up,
                                  **kwargs)
        member = self.deserialize(fmt or self.fmt, res)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        try:
            yield member
        finally:
            if not no_delete:
                self._delete('members', member['member']['id'])

    @contextlib.contextmanager
    def health_monitor(self, fmt=None, type='TCP',
                       delay=30, timeout=10, max_retries=3,
                       admin_state_up=True,
                       no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_health_monitor(fmt,
                                          type,
                                          delay,
                                          timeout,
                                          max_retries,
                                          admin_state_up,
                                          **kwargs)
        health_monitor = self.deserialize(fmt or self.fmt, res)
        the_health_monitor = health_monitor['health_monitor']
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        # make sure:
        # 1. When the type is HTTP/S we have HTTP related attributes in
        #    the result
        # 2. When the type is not HTTP/S we do not have HTTP related
        #    attributes in the result
        http_related_attributes = ('http_method', 'url_path', 'expected_codes')
        if type in ['HTTP', 'HTTPS']:
            for arg in http_related_attributes:
                self.assertIsNotNone(the_health_monitor.get(arg))
        else:
            for arg in http_related_attributes:
                self.assertIsNone(the_health_monitor.get(arg))
        try:
            yield health_monitor
        finally:
            if not no_delete:
                self._delete('health_monitors', the_health_monitor['id'])


class TestLoadBalancer(LoadBalancerPluginDbTestCase):
    def test_create_vip(self, **extras):
        expected = {
            'name': 'vip1',
            'description': '',
            'protocol_port': 80,
            'protocol': 'HTTP',
            'connection_limit': -1,
            'admin_state_up': True,
            'status': 'PENDING_CREATE',
            'tenant_id': self._tenant_id,
        }

        expected.update(extras)

        with self.subnet() as subnet:
            expected['subnet_id'] = subnet['subnet']['id']
            name = expected['name']

            with self.vip(name=name, subnet=subnet, **extras) as vip:
                for k in ('id', 'address', 'port_id', 'pool_id'):
                    self.assertTrue(vip['vip'].get(k, None))

                self.assertEqual(
                    dict((k, v)
                         for k, v in vip['vip'].items() if k in expected),
                    expected
                )
            return vip

    def test_create_vip_twice_for_same_pool(self):
        """ Test loadbalancer db plugin via extension and directly """
        with self.subnet() as subnet:
            with self.pool(name="pool1") as pool:
                with self.vip(name='vip1', subnet=subnet, pool=pool):
                    vip_data = {
                        'name': 'vip1',
                        'pool_id': pool['pool']['id'],
                        'description': '',
                        'protocol_port': 80,
                        'protocol': 'HTTP',
                        'connection_limit': -1,
                        'admin_state_up': True,
                        'status': 'PENDING_CREATE',
                        'tenant_id': self._tenant_id,
                        'session_persistence': ''
                    }
                    self.assertRaises(loadbalancer.VipExists,
                                      self.plugin.create_vip,
                                      context.get_admin_context(),
                                      {'vip': vip_data})

    def test_update_vip_raises_vip_exists(self):
        with self.subnet() as subnet:
            with contextlib.nested(
                self.pool(name="pool1"),
                self.pool(name="pool2")
            ) as (pool1, pool2):
                with contextlib.nested(
                    self.vip(name='vip1', subnet=subnet, pool=pool1),
                    self.vip(name='vip2', subnet=subnet, pool=pool2)
                ) as (vip1, vip2):
                    vip_data = {
                        'id': vip2['vip']['id'],
                        'name': 'vip1',
                        'pool_id': pool1['pool']['id'],
                    }
                    self.assertRaises(loadbalancer.VipExists,
                                      self.plugin.update_vip,
                                      context.get_admin_context(),
                                      vip2['vip']['id'],
                                      {'vip': vip_data})

    def test_update_vip_change_pool(self):
        with self.subnet() as subnet:
            with contextlib.nested(
                self.pool(name="pool1"),
                self.pool(name="pool2")
            ) as (pool1, pool2):
                with self.vip(name='vip1', subnet=subnet, pool=pool1) as vip:
                    # change vip from pool1 to pool2
                    vip_data = {
                        'id': vip['vip']['id'],
                        'name': 'vip1',
                        'pool_id': pool2['pool']['id'],
                    }
                    ctx = context.get_admin_context()
                    self.plugin.update_vip(ctx,
                                           vip['vip']['id'],
                                           {'vip': vip_data})
                    db_pool2 = (ctx.session.query(ldb.Pool).
                                filter_by(id=pool2['pool']['id']).one())
                    db_pool1 = (ctx.session.query(ldb.Pool).
                                filter_by(id=pool1['pool']['id']).one())
                    # check that pool1.vip became None
                    self.assertIsNone(db_pool1.vip)
                    # and pool2 got vip
                    self.assertEqual(db_pool2.vip.id, vip['vip']['id'])

    def test_create_vip_with_invalid_values(self):
        invalid = {
            'protocol': 'UNSUPPORTED',
            'protocol_port': 'NOT_AN_INT',
            'protocol_port': 1000500,
            'subnet': {'subnet': {'id': 'invalid-subnet'}}
        }

        for param, value in invalid.items():
            kwargs = {'name': 'the-vip', param: value}
            with testtools.ExpectedException(webob.exc.HTTPClientError):
                with self.vip(**kwargs):
                    pass

    def test_create_vip_with_address(self):
        self.test_create_vip(address='10.0.0.7')

    def test_create_vip_with_address_outside_subnet(self):
        with testtools.ExpectedException(webob.exc.HTTPClientError):
            self.test_create_vip(address='9.9.9.9')

    def test_create_vip_with_session_persistence(self):
        self.test_create_vip(session_persistence={'type': 'HTTP_COOKIE'})

    def test_create_vip_with_session_persistence_with_app_cookie(self):
        sp = {'type': 'APP_COOKIE', 'cookie_name': 'sessionId'}
        self.test_create_vip(session_persistence=sp)

    def test_create_vip_with_session_persistence_unsupported_type(self):
        with testtools.ExpectedException(webob.exc.HTTPClientError):
            self.test_create_vip(session_persistence={'type': 'UNSUPPORTED'})

    def test_create_vip_with_unnecessary_cookie_name(self):
        sp = {'type': "SOURCE_IP", 'cookie_name': 'sessionId'}
        with testtools.ExpectedException(webob.exc.HTTPClientError):
            self.test_create_vip(session_persistence=sp)

    def test_create_vip_with_session_persistence_without_cookie_name(self):
        sp = {'type': "APP_COOKIE"}
        with testtools.ExpectedException(webob.exc.HTTPClientError):
            self.test_create_vip(session_persistence=sp)

    def test_create_vip_with_protocol_mismatch(self):
        with self.pool(protocol='TCP') as pool:
            with testtools.ExpectedException(webob.exc.HTTPClientError):
                self.test_create_vip(pool=pool, protocol='HTTP')

    def test_update_vip_with_protocol_mismatch(self):
        with self.pool(protocol='TCP') as pool:
            with self.vip(protocol='HTTP') as vip:
                data = {'vip': {'pool_id': pool['pool']['id']}}
                req = self.new_update_request('vips', data, vip['vip']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 400)

    def test_reset_session_persistence(self):
        name = 'vip4'
        session_persistence = {'type': "HTTP_COOKIE"}

        update_info = {'vip': {'session_persistence': None}}

        with self.vip(name=name, session_persistence=session_persistence) as v:
            # Ensure that vip has been created properly
            self.assertEqual(v['vip']['session_persistence'],
                             session_persistence)

            # Try resetting session_persistence
            req = self.new_update_request('vips', update_info, v['vip']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))

            # If session persistence has been removed, it won't be present in
            # the response.
            self.assertNotIn('session_persistence', res['vip'])

    def test_update_vip(self):
        name = 'new_vip'
        keys = [('name', name),
                ('address', "10.0.0.2"),
                ('protocol_port', 80),
                ('connection_limit', 100),
                ('admin_state_up', False),
                ('status', 'PENDING_UPDATE')]

        with self.vip(name=name) as vip:
            keys.append(('subnet_id', vip['vip']['subnet_id']))
            data = {'vip': {'name': name,
                            'connection_limit': 100,
                            'session_persistence':
                            {'type': "APP_COOKIE",
                             'cookie_name': "jesssionId"},
                            'admin_state_up': False}}
            req = self.new_update_request('vips', data, vip['vip']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['vip'][k], v)

    def test_delete_vip(self):
        with self.pool():
            with self.vip(no_delete=True) as vip:
                req = self.new_delete_request('vips',
                                              vip['vip']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)

    def test_show_vip(self):
        name = "vip_show"
        keys = [('name', name),
                ('address', "10.0.0.10"),
                ('protocol_port', 80),
                ('protocol', 'HTTP'),
                ('connection_limit', -1),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.vip(name=name, address='10.0.0.10') as vip:
            req = self.new_show_request('vips',
                                        vip['vip']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['vip'][k], v)

    def test_list_vips(self):
        name = "vips_list"
        keys = [('name', name),
                ('address', "10.0.0.2"),
                ('protocol_port', 80),
                ('protocol', 'HTTP'),
                ('connection_limit', -1),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.vip(name=name) as vip:
            keys.append(('subnet_id', vip['vip']['subnet_id']))
            req = self.new_list_request('vips')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(len(res), 1)
            for k, v in keys:
                self.assertEqual(res['vips'][0][k], v)

    def test_list_vips_with_sort_emulated(self):
        with self.subnet() as subnet:
            with contextlib.nested(
                self.vip(name='vip1', subnet=subnet, protocol_port=81),
                self.vip(name='vip2', subnet=subnet, protocol_port=82),
                self.vip(name='vip3', subnet=subnet, protocol_port=82)
            ) as (vip1, vip2, vip3):
                self._test_list_with_sort(
                    'vip',
                    (vip1, vip3, vip2),
                    [('protocol_port', 'asc'), ('name', 'desc')]
                )

    def test_list_vips_with_pagination_emulated(self):
        with self.subnet() as subnet:
            with contextlib.nested(self.vip(name='vip1', subnet=subnet),
                                   self.vip(name='vip2', subnet=subnet),
                                   self.vip(name='vip3', subnet=subnet)
                                   ) as (vip1, vip2, vip3):
                self._test_list_with_pagination('vip',
                                                (vip1, vip2, vip3),
                                                ('name', 'asc'), 2, 2)

    def test_list_vips_with_pagination_reverse_emulated(self):
        with self.subnet() as subnet:
            with contextlib.nested(self.vip(name='vip1', subnet=subnet),
                                   self.vip(name='vip2', subnet=subnet),
                                   self.vip(name='vip3', subnet=subnet)
                                   ) as (vip1, vip2, vip3):
                self._test_list_with_pagination_reverse('vip',
                                                        (vip1, vip2, vip3),
                                                        ('name', 'asc'), 2, 2)

    def test_create_pool_with_invalid_values(self):
        name = 'pool3'

        pool = self.pool(name=name, protocol='UNSUPPORTED')
        self.assertRaises(webob.exc.HTTPClientError, pool.__enter__)

        pool = self.pool(name=name, lb_method='UNSUPPORTED')
        self.assertRaises(webob.exc.HTTPClientError, pool.__enter__)

    def test_create_pool(self):
        name = "pool1"
        keys = [('name', name),
                ('subnet_id', self._subnet_id),
                ('tenant_id', self._tenant_id),
                ('protocol', 'HTTP'),
                ('lb_method', 'ROUND_ROBIN'),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]

        with self.pool(name=name) as pool:
            for k, v in keys:
                self.assertEqual(pool['pool'][k], v)

    def test_create_pool_with_members(self):
        name = "pool2"
        with self.pool(name=name) as pool:
            pool_id = pool['pool']['id']
            res1 = self._create_member(self.fmt,
                                       '192.168.1.100',
                                       '80',
                                       True,
                                       pool_id=pool_id,
                                       weight=1)
            req = self.new_show_request('pools',
                                        pool_id,
                                        fmt=self.fmt)
            pool_updated = self.deserialize(
                self.fmt,
                req.get_response(self.ext_api)
            )

            member1 = self.deserialize(self.fmt, res1)
            self.assertEqual(member1['member']['id'],
                             pool_updated['pool']['members'][0])
            self.assertEqual(len(pool_updated['pool']['members']), 1)

            keys = [('address', '192.168.1.100'),
                    ('protocol_port', 80),
                    ('weight', 1),
                    ('pool_id', pool_id),
                    ('admin_state_up', True),
                    ('status', 'PENDING_CREATE')]
            for k, v in keys:
                self.assertEqual(member1['member'][k], v)
            self._delete('members', member1['member']['id'])

    def test_delete_pool(self):
        with self.pool(no_delete=True) as pool:
            with self.member(no_delete=True,
                             pool_id=pool['pool']['id']):
                req = self.new_delete_request('pools',
                                              pool['pool']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)

    def test_show_pool(self):
        name = "pool1"
        keys = [('name', name),
                ('subnet_id', self._subnet_id),
                ('tenant_id', self._tenant_id),
                ('protocol', 'HTTP'),
                ('lb_method', 'ROUND_ROBIN'),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.pool(name=name) as pool:
            req = self.new_show_request('pools',
                                        pool['pool']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['pool'][k], v)

    def test_list_pools_with_sort_emulated(self):
        with contextlib.nested(self.pool(name='p1'),
                               self.pool(name='p2'),
                               self.pool(name='p3')
                               ) as (p1, p2, p3):
            self._test_list_with_sort('pool', (p3, p2, p1),
                                      [('name', 'desc')])

    def test_list_pools_with_pagination_emulated(self):
        with contextlib.nested(self.pool(name='p1'),
                               self.pool(name='p2'),
                               self.pool(name='p3')
                               ) as (p1, p2, p3):
            self._test_list_with_pagination('pool',
                                            (p1, p2, p3),
                                            ('name', 'asc'), 2, 2)

    def test_list_pools_with_pagination_reverse_emulated(self):
        with contextlib.nested(self.pool(name='p1'),
                               self.pool(name='p2'),
                               self.pool(name='p3')
                               ) as (p1, p2, p3):
            self._test_list_with_pagination_reverse('pool',
                                                    (p1, p2, p3),
                                                    ('name', 'asc'), 2, 2)

    def test_create_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(address='192.168.1.100',
                             protocol_port=80,
                             pool_id=pool_id) as member1:
                with self.member(address='192.168.1.101',
                                 protocol_port=80,
                                 pool_id=pool_id) as member2:
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

    def test_update_member(self):
        with self.pool(name="pool1") as pool1:
            with self.pool(name="pool2") as pool2:
                keys = [('address', "192.168.1.100"),
                        ('tenant_id', self._tenant_id),
                        ('protocol_port', 80),
                        ('weight', 10),
                        ('pool_id', pool2['pool']['id']),
                        ('admin_state_up', False),
                        ('status', 'PENDING_UPDATE')]
                with self.member(pool_id=pool1['pool']['id']) as member:
                    req = self.new_show_request('pools',
                                                pool1['pool']['id'],
                                                fmt=self.fmt)
                    pool1_update = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )
                    self.assertEqual(len(pool1_update['pool']['members']), 1)

                    req = self.new_show_request('pools',
                                                pool2['pool']['id'],
                                                fmt=self.fmt)
                    pool2_update = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )
                    self.assertEqual(len(pool1_update['pool']['members']), 1)
                    self.assertEqual(len(pool2_update['pool']['members']), 0)

                    data = {'member': {'pool_id': pool2['pool']['id'],
                                       'weight': 10,
                                       'admin_state_up': False}}
                    req = self.new_update_request('members',
                                                  data,
                                                  member['member']['id'])
                    res = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )
                    for k, v in keys:
                        self.assertEqual(res['member'][k], v)

                    req = self.new_show_request('pools',
                                                pool1['pool']['id'],
                                                fmt=self.fmt)
                    pool1_update = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )

                    req = self.new_show_request('pools',
                                                pool2['pool']['id'],
                                                fmt=self.fmt)
                    pool2_update = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )

                    self.assertEqual(len(pool2_update['pool']['members']), 1)
                    self.assertEqual(len(pool1_update['pool']['members']), 0)

    def test_delete_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id,
                             no_delete=True) as member:
                req = self.new_delete_request('members',
                                              member['member']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)

                req = self.new_show_request('pools',
                                            pool_id,
                                            fmt=self.fmt)
                pool_update = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                self.assertEqual(len(pool_update['pool']['members']), 0)

    def test_show_member(self):
        with self.pool() as pool:
            keys = [('address', "192.168.1.100"),
                    ('tenant_id', self._tenant_id),
                    ('protocol_port', 80),
                    ('weight', 1),
                    ('pool_id', pool['pool']['id']),
                    ('admin_state_up', True),
                    ('status', 'PENDING_CREATE')]
            with self.member(pool_id=pool['pool']['id']) as member:
                req = self.new_show_request('members',
                                            member['member']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                for k, v in keys:
                    self.assertEqual(res['member'][k], v)

    def test_list_members_with_sort_emulated(self):
        with self.pool() as pool:
            with contextlib.nested(self.member(pool_id=pool['pool']['id'],
                                               protocol_port=81),
                                   self.member(pool_id=pool['pool']['id'],
                                               protocol_port=82),
                                   self.member(pool_id=pool['pool']['id'],
                                               protocol_port=83)
                                   ) as (m1, m2, m3):
                self._test_list_with_sort('member', (m3, m2, m1),
                                          [('protocol_port', 'desc')])

    def test_list_members_with_pagination_emulated(self):
        with self.pool() as pool:
            with contextlib.nested(self.member(pool_id=pool['pool']['id'],
                                               protocol_port=81),
                                   self.member(pool_id=pool['pool']['id'],
                                               protocol_port=82),
                                   self.member(pool_id=pool['pool']['id'],
                                               protocol_port=83)
                                   ) as (m1, m2, m3):
                self._test_list_with_pagination(
                    'member', (m1, m2, m3), ('protocol_port', 'asc'), 2, 2
                )

    def test_list_members_with_pagination_reverse_emulated(self):
        with self.pool() as pool:
            with contextlib.nested(self.member(pool_id=pool['pool']['id'],
                                               protocol_port=81),
                                   self.member(pool_id=pool['pool']['id'],
                                               protocol_port=82),
                                   self.member(pool_id=pool['pool']['id'],
                                               protocol_port=83)
                                   ) as (m1, m2, m3):
                self._test_list_with_pagination_reverse(
                    'member', (m1, m2, m3), ('protocol_port', 'asc'), 2, 2
                )

    def test_create_healthmonitor(self):
        keys = [('type', "TCP"),
                ('tenant_id', self._tenant_id),
                ('delay', 30),
                ('timeout', 10),
                ('max_retries', 3),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.health_monitor() as monitor:
            for k, v in keys:
                self.assertEqual(monitor['health_monitor'][k], v)

    def test_update_healthmonitor(self):
        keys = [('type', "TCP"),
                ('tenant_id', self._tenant_id),
                ('delay', 20),
                ('timeout', 20),
                ('max_retries', 2),
                ('admin_state_up', False),
                ('status', 'PENDING_UPDATE')]
        with self.health_monitor() as monitor:
            data = {'health_monitor': {'delay': 20,
                                       'timeout': 20,
                                       'max_retries': 2,
                                       'admin_state_up': False}}
            req = self.new_update_request("health_monitors",
                                          data,
                                          monitor['health_monitor']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['health_monitor'][k], v)

    def test_delete_healthmonitor(self):
        with self.health_monitor(no_delete=True) as monitor:
            req = self.new_delete_request('health_monitors',
                                          monitor['health_monitor']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_show_healthmonitor(self):
        with self.health_monitor() as monitor:
            keys = [('type', "TCP"),
                    ('tenant_id', self._tenant_id),
                    ('delay', 30),
                    ('timeout', 10),
                    ('max_retries', 3),
                    ('admin_state_up', True),
                    ('status', 'PENDING_CREATE')]
            req = self.new_show_request('health_monitors',
                                        monitor['health_monitor']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['health_monitor'][k], v)

    def test_list_healthmonitors_with_sort_emulated(self):
        with contextlib.nested(self.health_monitor(delay=30),
                               self.health_monitor(delay=31),
                               self.health_monitor(delay=32)
                               ) as (m1, m2, m3):
            self._test_list_with_sort('health_monitor', (m3, m2, m1),
                                      [('delay', 'desc')])

    def test_list_healthmonitors_with_pagination_emulated(self):
        with contextlib.nested(self.health_monitor(delay=30),
                               self.health_monitor(delay=31),
                               self.health_monitor(delay=32)
                               ) as (m1, m2, m3):
            self._test_list_with_pagination('health_monitor',
                                            (m1, m2, m3),
                                            ('delay', 'asc'), 2, 2)

    def test_list_healthmonitors_with_pagination_reverse_emulated(self):
        with contextlib.nested(self.health_monitor(delay=30),
                               self.health_monitor(delay=31),
                               self.health_monitor(delay=32)
                               ) as (m1, m2, m3):
            self._test_list_with_pagination_reverse('health_monitor',
                                                    (m1, m2, m3),
                                                    ('delay', 'asc'), 2, 2)

    def test_get_pool_stats(self):
        keys = [("bytes_in", 0),
                ("bytes_out", 0),
                ("active_connections", 0),
                ("total_connections", 0)]
        with self.pool() as pool:
            req = self.new_show_request("pools",
                                        pool['pool']['id'],
                                        subresource="stats",
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['stats'][k], v)

    def test_create_healthmonitor_of_pool(self):
        with self.health_monitor(type="TCP") as monitor1:
            with self.health_monitor(type="HTTP") as monitor2:
                with self.pool() as pool:
                    data = {"health_monitor": {
                            "id": monitor1['health_monitor']['id'],
                            'tenant_id': self._tenant_id}}
                    req = self.new_create_request(
                        "pools",
                        data,
                        fmt=self.fmt,
                        id=pool['pool']['id'],
                        subresource="health_monitors")
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 201)

                    data = {"health_monitor": {
                            "id": monitor2['health_monitor']['id'],
                            'tenant_id': self._tenant_id}}
                    req = self.new_create_request(
                        "pools",
                        data,
                        fmt=self.fmt,
                        id=pool['pool']['id'],
                        subresource="health_monitors")
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 201)

                    req = self.new_show_request(
                        'pools',
                        pool['pool']['id'],
                        fmt=self.fmt)
                    res = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )
                    self.assertIn(monitor1['health_monitor']['id'],
                                  res['pool']['health_monitors'])
                    self.assertIn(monitor2['health_monitor']['id'],
                                  res['pool']['health_monitors'])

    def test_delete_healthmonitor_of_pool(self):
        with self.health_monitor(type="TCP") as monitor1:
            with self.health_monitor(type="HTTP") as monitor2:
                with self.pool() as pool:
                    # add the monitors to the pool
                    data = {"health_monitor": {
                            "id": monitor1['health_monitor']['id'],
                            'tenant_id': self._tenant_id}}
                    req = self.new_create_request(
                        "pools",
                        data,
                        fmt=self.fmt,
                        id=pool['pool']['id'],
                        subresource="health_monitors")
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 201)

                    data = {"health_monitor": {
                            "id": monitor2['health_monitor']['id'],
                            'tenant_id': self._tenant_id}}
                    req = self.new_create_request(
                        "pools",
                        data,
                        fmt=self.fmt,
                        id=pool['pool']['id'],
                        subresource="health_monitors")
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 201)

                    # remove one of healthmonitor from the pool
                    req = self.new_delete_request(
                        "pools",
                        fmt=self.fmt,
                        id=pool['pool']['id'],
                        sub_id=monitor1['health_monitor']['id'],
                        subresource="health_monitors")
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 204)

                    req = self.new_show_request(
                        'pools',
                        pool['pool']['id'],
                        fmt=self.fmt)
                    res = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )
                    self.assertNotIn(monitor1['health_monitor']['id'],
                                     res['pool']['health_monitors'])
                    self.assertIn(monitor2['health_monitor']['id'],
                                  res['pool']['health_monitors'])

    def test_create_loadbalancer(self):
        vip_name = "vip3"
        pool_name = "pool3"

        with self.pool(name=pool_name) as pool:
            with self.vip(name=vip_name, pool=pool) as vip:
                pool_id = pool['pool']['id']
                vip_id = vip['vip']['id']
                # Add two members
                res1 = self._create_member(self.fmt,
                                           '192.168.1.100',
                                           '80',
                                           True,
                                           pool_id=pool_id,
                                           weight=1)
                res2 = self._create_member(self.fmt,
                                           '192.168.1.101',
                                           '80',
                                           True,
                                           pool_id=pool_id,
                                           weight=2)
                # Add a health_monitor
                req = self._create_health_monitor(self.fmt,
                                                  'HTTP',
                                                  '10',
                                                  '10',
                                                  '3',
                                                  True)
                health_monitor = self.deserialize(self.fmt, req)
                self.assertEqual(req.status_int, 201)

                # Associate the health_monitor to the pool
                data = {"health_monitor": {
                        "id": health_monitor['health_monitor']['id'],
                        'tenant_id': self._tenant_id}}
                req = self.new_create_request("pools",
                                              data,
                                              fmt=self.fmt,
                                              id=pool['pool']['id'],
                                              subresource="health_monitors")
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 201)

                # Get pool and vip
                req = self.new_show_request('pools',
                                            pool_id,
                                            fmt=self.fmt)
                pool_updated = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                member1 = self.deserialize(self.fmt, res1)
                member2 = self.deserialize(self.fmt, res2)
                self.assertIn(member1['member']['id'],
                              pool_updated['pool']['members'])
                self.assertIn(member2['member']['id'],
                              pool_updated['pool']['members'])
                self.assertIn(health_monitor['health_monitor']['id'],
                              pool_updated['pool']['health_monitors'])

                req = self.new_show_request('vips',
                                            vip_id,
                                            fmt=self.fmt)
                vip_updated = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                self.assertEqual(vip_updated['vip']['pool_id'],
                                 pool_updated['pool']['id'])

                # clean up
                self._delete('health_monitors',
                             health_monitor['health_monitor']['id'])
                self._delete('members', member1['member']['id'])
                self._delete('members', member2['member']['id'])


class TestLoadBalancerXML(TestLoadBalancer):
    fmt = 'xml'
