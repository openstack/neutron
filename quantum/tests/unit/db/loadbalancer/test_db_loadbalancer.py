# Copyright (c) 2012 OpenStack, LLC.
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

from oslo.config import cfg
import webob.exc

from quantum.api.extensions import ExtensionMiddleware
from quantum.api.extensions import PluginAwareExtensionManager
from quantum.api.v2 import attributes
from quantum.api.v2.router import APIRouter
from quantum.common import config
from quantum.common.test_lib import test_config
from quantum.db import api as db
import quantum.extensions
from quantum.extensions import loadbalancer
from quantum.manager import QuantumManager
from quantum.plugins.common import constants
from quantum.plugins.services.loadbalancer import loadbalancerPlugin
from quantum.tests.unit import testlib_api
from quantum.tests.unit.testlib_api import create_request
from quantum import wsgi


LOG = logging.getLogger(__name__)

DB_CORE_PLUGIN_KLASS = 'quantum.db.db_base_plugin_v2.QuantumDbPluginV2'
DB_LB_PLUGIN_KLASS = (
    "quantum.plugins.services.loadbalancer."
    "loadbalancerPlugin.LoadBalancerPlugin"
)
ROOTDIR = os.path.dirname(__file__) + '../../../..'
ETCDIR = os.path.join(ROOTDIR, 'etc')

extensions_path = ':'.join(quantum.extensions.__path__)


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class LoadBalancerPluginDbTestCase(testlib_api.WebTestCase):

    def setUp(self, core_plugin=None, lb_plugin=None):
        super(LoadBalancerPluginDbTestCase, self).setUp()

        db._ENGINE = None
        db._MAKER = None

        QuantumManager._instance = None
        PluginAwareExtensionManager._instance = None
        self._attribute_map_bk = {}
        self._attribute_map_bk = loadbalancer.RESOURCE_ATTRIBUTE_MAP.copy()
        self._tenant_id = "test-tenant"
        self._subnet_id = "0c798ed8-33ba-11e2-8b28-000c291c4d14"

        if not core_plugin:
            core_plugin = test_config.get('plugin_name_v2',
                                          DB_CORE_PLUGIN_KLASS)
        if not lb_plugin:
            lb_plugin = test_config.get('lb_plugin_name', DB_LB_PLUGIN_KLASS)

        # point config file to: quantum/tests/etc/quantum.conf.test
        args = ['--config-file', etcdir('quantum.conf.test')]
        config.parse(args=args)
        # Update the plugin
        service_plugins = [lb_plugin]
        cfg.CONF.set_override('core_plugin', core_plugin)
        cfg.CONF.set_override('service_plugins', service_plugins)
        cfg.CONF.set_override('base_mac', "12:34:56:78:90:ab")
        self.api = APIRouter()

        plugin = loadbalancerPlugin.LoadBalancerPlugin()
        ext_mgr = PluginAwareExtensionManager(
            extensions_path,
            {constants.LOADBALANCER: plugin}
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = ExtensionMiddleware(app, ext_mgr=ext_mgr)
        super(LoadBalancerPluginDbTestCase, self).setUp()

    def tearDown(self):
        super(LoadBalancerPluginDbTestCase, self).tearDown()
        self.api = None
        self._skip_native_bulk = None
        self.ext_api = None

        db.clear_db()
        db._ENGINE = None
        db._MAKER = None
        cfg.CONF.reset()
        # Restore the original attribute map
        loadbalancer.RESOURCE_ATTRIBUTE_MAP = self._attribute_map_bk

    def _req(self, method, resource, data=None, fmt=None,
             id=None, subresource=None, sub_id=None, params=None, action=None):
        if not fmt:
            fmt = self.fmt
        if id and action:
            path = '/lb/%(resource)s/%(id)s/%(action)s.%(fmt)s' % locals()
        elif id and subresource and sub_id:
            path = (
                '/lb/%(resource)s/%(id)s/%(subresource)s/'
                '%(sub_id)s.%(fmt)s') % locals()
        elif id and subresource:
            path = (
                '/lb/%(resource)s/%(id)s/'
                '%(subresource)s.%(fmt)s') % locals()
        elif id:
            path = '/lb/%(resource)s/%(id)s.%(fmt)s' % locals()
        else:
            path = '/lb/%(resource)s.%(fmt)s' % locals()

        content_type = 'application/%s' % fmt
        body = None
        if data is not None:  # empty dict is valid
            body = wsgi.Serializer(
                attributes.get_attr_metadata()).serialize(data, content_type)

        req = create_request(path,
                             body,
                             content_type,
                             method,
                             query_string=params)
        return req

    def new_create_request(self, resource, data, fmt=None, id=None,
                           subresource=None):
        return self._req('POST', resource, data, fmt, id=id,
                         subresource=subresource)

    def new_list_request(self, resource, fmt=None, params=None):
        return self._req('GET', resource, None, fmt, params=params)

    def new_show_request(self, resource, id, fmt=None, action=None,
                         subresource=None, sub_id=None):
        return self._req('GET', resource, None, fmt, id=id, action=action,
                         subresource=subresource, sub_id=sub_id)

    def new_delete_request(self, resource, id, fmt=None,
                           subresource=None, sub_id=None):
        return self._req('DELETE', resource, None, fmt, id=id,
                         subresource=subresource, sub_id=sub_id)

    def new_update_request(self, resource, data, id, fmt=None):
        return self._req('PUT', resource, data, fmt, id=id)

    def _create_vip(self, fmt, name, pool_id, protocol, port, admin_state_up,
                    expected_res_status=None, **kwargs):
        data = {'vip': {'name': name,
                        'subnet_id': self._subnet_id,
                        'pool_id': pool_id,
                        'protocol': protocol,
                        'port': port,
                        'admin_state_up': admin_state_up,
                        'tenant_id': self._tenant_id}}
        for arg in ('description', 'address',
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

    def _create_member(self, fmt, address, port, admin_state_up,
                       expected_res_status=None, **kwargs):
        data = {'member': {'address': address,
                           'port': port,
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

    def _delete(self, collection, id,
                expected_code=webob.exc.HTTPNoContent.code):
        req = self.new_delete_request(collection, id)
        res = req.get_response(self._api_for_resource(collection))
        self.assertEqual(res.status_int, expected_code)

    def _show(self, resource, id, expected_code=webob.exc.HTTPOk.code):
        req = self.new_show_request(resource, id)
        res = req.get_response(self._api_for_resource(resource))
        self.assertEqual(res.status_int, expected_code)
        return self.deserialize(res)

    def _update(self, resource, id, new_data,
                expected_code=webob.exc.HTTPOk.code):
        req = self.new_update_request(resource, new_data, id)
        res = req.get_response(self._api_for_resource(resource))
        self.assertEqual(res.status_int, expected_code)
        return self.deserialize(res)

    def _list(self, resource, fmt=None, query_params=None):
        req = self.new_list_request(resource, fmt, query_params)
        res = req.get_response(self._api_for_resource(resource))
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
        return self.deserialize(res)

    @contextlib.contextmanager
    def vip(self, fmt=None, name='vip1', pool=None,
            protocol='HTTP', port=80, admin_state_up=True, no_delete=False,
            address="172.16.1.123", **kwargs):
        if not fmt:
            fmt = self.fmt
        if not pool:
            with self.pool() as pool:
                pool_id = pool['pool']['id']
                res = self._create_vip(fmt,
                                       name,
                                       pool_id,
                                       protocol,
                                       port,
                                       admin_state_up,
                                       address=address,
                                       **kwargs)
                vip = self.deserialize(res)
                if res.status_int >= 400:
                    raise webob.exc.HTTPClientError(code=res.status_int)
                yield vip
                if not no_delete:
                    self._delete('vips', vip['vip']['id'])
        else:
            pool_id = pool['pool']['id']
            res = self._create_vip(fmt,
                                   name,
                                   pool_id,
                                   protocol,
                                   port,
                                   admin_state_up,
                                   address=address,
                                   **kwargs)
            vip = self.deserialize(res)
            if res.status_int >= 400:
                raise webob.exc.HTTPClientError(code=res.status_int)
            yield vip
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
        pool = self.deserialize(res)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        yield pool
        if not no_delete:
            self._delete('pools', pool['pool']['id'])

    @contextlib.contextmanager
    def member(self, fmt=None, address='192.168.1.100',
               port=80, admin_state_up=True, no_delete=False,
               **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_member(fmt,
                                  address,
                                  port,
                                  admin_state_up,
                                  **kwargs)
        member = self.deserialize(res)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        yield member
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
        health_monitor = self.deserialize(res)
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
        yield health_monitor
        if not no_delete:
            self._delete('health_monitors', the_health_monitor['id'])


class TestLoadBalancer(LoadBalancerPluginDbTestCase):
    def test_create_vip(self):
        name = 'vip1'
        keys = [('name', name),
                ('subnet_id', self._subnet_id),
                ('address', "172.16.1.123"),
                ('port', 80),
                ('protocol', 'HTTP'),
                ('connection_limit', -1),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]

        with self.vip(name=name) as vip:
            for k, v in keys:
                self.assertEqual(vip['vip'][k], v)

    def test_create_vip_with_invalid_values(self):
        name = 'vip3'

        vip = self.vip(name=name, protocol='UNSUPPORTED')
        self.assertRaises(webob.exc.HTTPClientError, vip.__enter__)

        vip = self.vip(name=name, port='NOT_AN_INT')
        self.assertRaises(webob.exc.HTTPClientError, vip.__enter__)

        # 100500 is not a valid port number
        vip = self.vip(name=name, port='100500')
        self.assertRaises(webob.exc.HTTPClientError, vip.__enter__)

        # 192.168.130.130.130 is not a valid IP address
        vip = self.vip(name=name, address='192.168.130.130.130')
        self.assertRaises(webob.exc.HTTPClientError, vip.__enter__)

    def test_create_vip_with_session_persistence(self):
        name = 'vip2'
        keys = [('name', name),
                ('subnet_id', self._subnet_id),
                ('address', "172.16.1.123"),
                ('port', 80),
                ('protocol', 'HTTP'),
                ('session_persistence', {'type': "HTTP_COOKIE"}),
                ('connection_limit', -1),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]

        with self.vip(name=name,
                      session_persistence={'type': "HTTP_COOKIE"}) as vip:
            for k, v in keys:
                self.assertEqual(vip['vip'][k], v)

    def test_create_vip_with_session_persistence_with_app_cookie(self):
        name = 'vip7'
        keys = [('name', name),
                ('subnet_id', self._subnet_id),
                ('address', "172.16.1.123"),
                ('port', 80),
                ('protocol', 'HTTP'),
                ('session_persistence', {'type': "APP_COOKIE",
                                         'cookie_name': 'sessionId'}),
                ('connection_limit', -1),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]

        with self.vip(name=name,
                      session_persistence={'type': "APP_COOKIE",
                                           'cookie_name': 'sessionId'}) as vip:
            for k, v in keys:
                self.assertEqual(vip['vip'][k], v)

    def test_create_vip_with_session_persistence_unsupported_type(self):
        name = 'vip5'

        vip = self.vip(name=name, session_persistence={'type': "UNSUPPORTED"})
        self.assertRaises(webob.exc.HTTPClientError, vip.__enter__)

    def test_create_vip_with_unnecessary_cookie_name(self):
        name = 'vip8'

        s_p = {'type': "SOURCE_IP", 'cookie_name': 'sessionId'}
        vip = self.vip(name=name, session_persistence=s_p)

        self.assertRaises(webob.exc.HTTPClientError, vip.__enter__)

    def test_create_vip_with_session_persistence_without_cookie_name(self):
        name = 'vip6'

        vip = self.vip(name=name, session_persistence={'type': "APP_COOKIE"})
        self.assertRaises(webob.exc.HTTPClientError, vip.__enter__)

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
            res = self.deserialize(req.get_response(self.ext_api))

            # If session persistence has been removed, it won't be present in
            # the response.
            self.assertNotIn('session_persistence', res['vip'])

    def test_update_vip(self):
        name = 'new_vip'
        keys = [('name', name),
                ('subnet_id', self._subnet_id),
                ('address', "172.16.1.123"),
                ('port', 80),
                ('connection_limit', 100),
                ('admin_state_up', False),
                ('status', 'PENDING_UPDATE')]

        with self.vip(name=name) as vip:
            data = {'vip': {'name': name,
                            'connection_limit': 100,
                            'session_persistence':
                            {'type': "APP_COOKIE",
                             'cookie_name': "jesssionId"},
                            'admin_state_up': False}}
            req = self.new_update_request('vips', data, vip['vip']['id'])
            res = self.deserialize(req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['vip'][k], v)

    def test_delete_vip(self):
        with self.pool() as pool:
            with self.vip(no_delete=True) as vip:
                req = self.new_delete_request('vips',
                                              vip['vip']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)

    def test_show_vip(self):
        name = "vip_show"
        keys = [('name', name),
                ('subnet_id', self._subnet_id),
                ('address', "172.16.1.123"),
                ('port', 80),
                ('protocol', 'HTTP'),
                ('connection_limit', -1),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.vip(name=name) as vip:
            req = self.new_show_request('vips',
                                        vip['vip']['id'])
            res = self.deserialize(req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['vip'][k], v)

    def test_list_vips(self):
        name = "vips_list"
        keys = [('name', name),
                ('subnet_id', self._subnet_id),
                ('address', "172.16.1.123"),
                ('port', 80),
                ('protocol', 'HTTP'),
                ('connection_limit', -1),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.vip(name=name):
            req = self.new_list_request('vips')
            res = self.deserialize(req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['vips'][0][k], v)

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
            pool_updated = self.deserialize(req.get_response(self.ext_api))

            member1 = self.deserialize(res1)
            self.assertEqual(member1['member']['id'],
                             pool_updated['pool']['members'][0])
            self.assertEqual(len(pool_updated['pool']['members']), 1)

            keys = [('address', '192.168.1.100'),
                    ('port', 80),
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
                             pool_id=pool['pool']['id']) as member:
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
            res = self.deserialize(req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['pool'][k], v)

    def test_create_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(address='192.168.1.100',
                             port=80,
                             pool_id=pool_id) as member1:
                with self.member(address='192.168.1.101',
                                 port=80,
                                 pool_id=pool_id) as member2:
                    req = self.new_show_request('pools',
                                                pool_id,
                                                fmt=self.fmt)
                    pool_update = self.deserialize(
                        req.get_response(self.ext_api))
                    self.assertIn(member1['member']['id'],
                                  pool_update['pool']['members'])
                    self.assertIn(member2['member']['id'],
                                  pool_update['pool']['members'])

    def test_update_member(self):
        with self.pool(name="pool1") as pool1:
            with self.pool(name="pool2") as pool2:
                keys = [('address', "192.168.1.100"),
                        ('tenant_id', self._tenant_id),
                        ('port', 80),
                        ('weight', 10),
                        ('pool_id', pool2['pool']['id']),
                        ('admin_state_up', False),
                        ('status', 'PENDING_UPDATE')]
                with self.member(pool_id=pool1['pool']['id']) as member:
                    req = self.new_show_request('pools',
                                                pool1['pool']['id'],
                                                fmt=self.fmt)
                    pool1_update = self.deserialize(
                        req.get_response(self.ext_api))
                    self.assertEqual(len(pool1_update['pool']['members']), 1)

                    req = self.new_show_request('pools',
                                                pool2['pool']['id'],
                                                fmt=self.fmt)
                    pool2_update = self.deserialize(
                        req.get_response(self.ext_api))
                    self.assertEqual(len(pool1_update['pool']['members']), 1)
                    self.assertEqual(len(pool2_update['pool']['members']), 0)

                    data = {'member': {'pool_id': pool2['pool']['id'],
                                       'weight': 10,
                                       'admin_state_up': False}}
                    req = self.new_update_request('members',
                                                  data,
                                                  member['member']['id'])
                    res = self.deserialize(req.get_response(self.ext_api))
                    for k, v in keys:
                        self.assertEqual(res['member'][k], v)

                    req = self.new_show_request('pools',
                                                pool1['pool']['id'],
                                                fmt=self.fmt)
                    pool1_update = self.deserialize(
                        req.get_response(self.ext_api))

                    req = self.new_show_request('pools',
                                                pool2['pool']['id'],
                                                fmt=self.fmt)
                    pool2_update = self.deserialize(
                        req.get_response(self.ext_api))

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
                    req.get_response(self.ext_api))
                self.assertEqual(len(pool_update['pool']['members']), 0)

    def test_show_member(self):
        with self.pool() as pool:
            keys = [('address', "192.168.1.100"),
                    ('tenant_id', self._tenant_id),
                    ('port', 80),
                    ('weight', 1),
                    ('pool_id', pool['pool']['id']),
                    ('admin_state_up', True),
                    ('status', 'PENDING_CREATE')]
            with self.member(pool_id=pool['pool']['id']) as member:
                req = self.new_show_request('members',
                                            member['member']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['member'][k], v)

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
            res = self.deserialize(req.get_response(self.ext_api))
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
            res = self.deserialize(req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['health_monitor'][k], v)

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
            res = self.deserialize(req.get_response(self.ext_api))
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
                    res = self.deserialize(req.get_response(self.ext_api))
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
                    res = self.deserialize(req.get_response(self.ext_api))
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
                health_monitor = self.deserialize(req)
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
                pool_updated = self.deserialize(req.get_response(self.ext_api))
                member1 = self.deserialize(res1)
                member2 = self.deserialize(res2)
                self.assertIn(member1['member']['id'],
                              pool_updated['pool']['members'])
                self.assertIn(member2['member']['id'],
                              pool_updated['pool']['members'])
                self.assertIn(health_monitor['health_monitor']['id'],
                              pool_updated['pool']['health_monitors'])

                req = self.new_show_request('vips',
                                            vip_id,
                                            fmt=self.fmt)
                vip_updated = self.deserialize(req.get_response(self.ext_api))
                self.assertEqual(vip_updated['vip']['pool_id'],
                                 pool_updated['pool']['id'])

                # clean up
                self._delete('health_monitors',
                             health_monitor['health_monitor']['id'])
                self._delete('members', member1['member']['id'])
                self._delete('members', member2['member']['id'])


class TestLoadBalancerXML(TestLoadBalancer):
    fmt = 'xml'
