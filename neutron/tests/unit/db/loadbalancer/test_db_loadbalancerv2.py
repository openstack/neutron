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

from oslo.config import cfg
import testtools
import webob.exc

from neutron.api import extensions
from neutron.common import config
from neutron import context
import neutron.db.l3_db  # noqa
from neutron.db.loadbalancer import loadbalancer_dbv2 as ldb
from neutron.db import servicetype_db as sdb
import neutron.extensions
from neutron.extensions import loadbalancerv2
from neutron.plugins.common import constants
from neutron.services.loadbalancer import constants as lb_const
from neutron.services.loadbalancer import plugin as loadbalancer_plugin

from neutron.tests.unit import test_db_plugin


LOG = logging.getLogger(__name__)

DB_CORE_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
DB_LB_PLUGIN_KLASS = (
    "neutron.services.loadbalancer."
    "plugin.LoadBalancerPluginv2"
)
NOOP_DRIVER_KLASS = ('neutron.tests.unit.db.loadbalancer.'
                     'test_db_loadbalancerv2.NoopLbaaSDriver')

extensions_path = ':'.join(neutron.extensions.__path__)

_subnet_id = "0c798ed8-33ba-11e2-8b28-000c291c4d14"


class BaseManager(object):

    def __init__(self, plugin):
        self.plugin = plugin


class NoopLoadBalancerManager(BaseManager):

    def create(self, context, load_balancer):
        self.plugin.update_status(context, ldb.LoadBalancer,
                                  load_balancer.id, constants.ACTIVE)

    def update(self, context, load_balancer, old_load_balancer):
        self.plugin.update_status(context, ldb.LoadBalancer,
                                  load_balancer.id, constants.ACTIVE)

    def delete(self, context, load_balancer):
        self.plugin._delete_db_loadbalancer(context, load_balancer.id)

    def stats(self, context, load_balancer_id):
        return {
            "bytes_in": 0,
            "bytes_out": 0,
            "active_connections": 0,
            "total_connections": 0
        }


class NoopListenerManager(BaseManager):

    def create(self, context, listener):
        self.plugin.update_status(context, ldb.Listener,
                                  listener.id, constants.ACTIVE)

    def update(self, context, listener, old_listener):
        self.plugin.update_status(context, ldb.Listener,
                                  listener.id, constants.ACTIVE)

    def delete(self, context, listener):
        self.plugin._delete_db_listener(context, listener.id)


class NoopPoolManager(BaseManager):

    def create(self, context, pool):
        self.plugin.update_status(context, ldb.PoolV2,
                                  pool.id, constants.ACTIVE)

    def update(self, context, pool, old_pool):
        self.plugin.update_status(context, ldb.PoolV2,
                                  pool.id, constants.ACTIVE)

    def delete(self, context, pool):
        self.plugin._delete_db_pool(context, pool.id)


class NoopMemberManager(BaseManager):

    def create(self, context, member):
        self.plugin.update_status(context, ldb.MemberV2,
                                  member.id, constants.ACTIVE)

    def update(self, context, member, old_member):
        self.plugin.update_status(context, ldb.MemberV2,
                                  member.id, constants.ACTIVE)

    def delete(self, context, member):
        self.plugin.delete_member(context, member.id)


class NoopHealthMonitorManager(BaseManager):

    def create(self, context, health_monitor):
        self.plugin.update_status(context, ldb.HealthMonitorV2,
                                  health_monitor.id, constants.ACTIVE)

    def update(self, context, health_monitor, old_health_monitor):
        self.plugin.update_status(context, ldb.HealthMonitorV2,
                                  health_monitor.id, constants.ACTIVE)

    def delete(self, context, health_monitor):
        self.plugin._delete_db_healthmonitor(context, health_monitor.id)


class NoopLbaaSDriver(object):
    """A dummy lbass driver that that only performs object deletion."""

    def __init__(self, plugin):
        self.plugin = plugin
        self.load_balancer = NoopLoadBalancerManager(plugin)
        self.listener = NoopListenerManager(plugin)
        self.pool = NoopPoolManager(plugin)
        self.member = NoopMemberManager(plugin)
        self.health_monitor = NoopHealthMonitorManager(plugin)


class LbaasTestMixin(object):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.LOADBALANCERv2])
        for k in loadbalancerv2.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def _get_loadbalancer_optional_args(self):
        return ('description', 'vip_address', 'admin_state_up', 'name')

    def _create_loadbalancer(self, fmt, subnet_id,
                             expected_res_status=None, **kwargs):
        data = {'loadbalancer': {'vip_subnet_id': subnet_id,
                                 'tenant_id': self._tenant_id}}
        args = self._get_loadbalancer_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['loadbalancer'][arg] = kwargs[arg]

        lb_req = self.new_create_request('loadbalancers', data, fmt)
        lb_res = lb_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(lb_res.status_int, expected_res_status)

        return lb_res

    def _get_listener_optional_args(self):
        return ('name', 'description', 'default_pool_id', 'loadbalancer_id',
                'connection_limit', 'admin_state_up')

    def _create_listener(self, fmt, protocol, protocol_port,
                         expected_res_status=None, **kwargs):
        data = {'listener': {'protocol': protocol,
                             'protocol_port': protocol_port,
                             'tenant_id': self._tenant_id}}
        args = self._get_listener_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['listener'][arg] = kwargs[arg]

        listener_req = self.new_create_request('listeners', data, fmt)
        listener_res = listener_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(listener_res.status_int, expected_res_status)

        return listener_res

    def _get_pool_optional_args(self):
        return ('name', 'description', 'healthmonitor_id', 'admin_state_up',
                'session_persistence')

    def _create_pool(self, fmt, protocol, lb_algorithm,
                     expected_res_status=None, **kwargs):
        data = {'pool': {'protocol': protocol,
                         'lb_algorithm': lb_algorithm,
                         'tenant_id': self._tenant_id}}

        args = self._get_pool_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['pool'][arg] = kwargs[arg]

        pool_req = self.new_create_request('pools', data, fmt)
        pool_res = pool_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(pool_res.status_int, expected_res_status)

        return pool_res

    def _get_member_optional_args(self):
        return ('weight', 'admin_state_up')

    def _create_member(self, fmt, pool_id, address, protocol_port, subnet_id,
                       expected_res_status=None, **kwargs):
        data = {'member': {'address': address,
                           'protocol_port': protocol_port,
                           'subnet_id': subnet_id,
                           'tenant_id': self._tenant_id}}

        args = self._get_member_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['member'][arg] = kwargs[arg]

        member_req = self.new_create_request('pools',
                                             data,
                                             fmt=fmt,
                                             id=pool_id,
                                             subresource='members')
        member_res = member_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(member_res.status_int, expected_res_status)

        return member_res

    def _get_healthmonitor_optional_args(self):
        return ('weight', 'admin_state_up', 'expected_codes', 'url_path',
                'http_method')

    def _create_healthmonitor(self, fmt, type, delay, timeout, max_retries,
                              expected_res_status=None, **kwargs):
        data = {'healthmonitor': {'type': type,
                                  'delay': delay,
                                  'timeout': timeout,
                                  'max_retries': max_retries,
                                  'tenant_id': self._tenant_id}}

        args = self._get_healthmonitor_optional_args()
        for arg in args:
            if arg in kwargs and kwargs[arg] is not None:
                data['healthmonitor'][arg] = kwargs[arg]

        hm_req = self.new_create_request('healthmonitors', data, fmt)
        hm_res = hm_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(hm_res.status_int, expected_res_status)

        return hm_res

    @contextlib.contextmanager
    def loadbalancer(self, fmt=None, subnet=None, no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        with test_db_plugin.optional_ctx(subnet, self.subnet) as tmp_subnet:
            res = self._create_loadbalancer(fmt,
                                            tmp_subnet['subnet']['id'],
                                            **kwargs)
            if res.status_int >= webob.exc.HTTPClientError.code:
                raise webob.exc.HTTPClientError(
                    explanation=_("Unexpected error code: %s") %
                    res.status_int
                )
            lb = self.deserialize(fmt or self.fmt, res)
            yield lb
            if not no_delete:
                self.plugin.update_status(context.get_admin_context(),
                                          ldb.LoadBalancer,
                                          lb['loadbalancer']['id'],
                                          constants.ACTIVE)
                self._delete('loadbalancers', lb['loadbalancer']['id'])

    @contextlib.contextmanager
    def listener(self, fmt=None, protocol='HTTP', protocol_port=80,
                 no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_listener(fmt,
                                    protocol=protocol,
                                    protocol_port=protocol_port,
                                    **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(
                explanation=_("Unexpected error code: %s") % res.status_int
            )

        listener = self.deserialize(fmt or self.fmt, res)
        yield listener
        if not no_delete:
            self.plugin.update_status(context.get_admin_context(),
                                      ldb.Listener,
                                      listener['listener']['id'],
                                      constants.ACTIVE)
            self._delete('listeners', listener['listener']['id'])

    @contextlib.contextmanager
    def pool(self, fmt=None, protocol='TCP', lb_algorithm='ROUND_ROBIN',
             no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_pool(fmt,
                                protocol=protocol,
                                lb_algorithm=lb_algorithm,
                                **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(
                explanation=_("Unexpected error code: %s") % res.status_int
            )

        pool = self.deserialize(fmt or self.fmt, res)
        yield pool
        if not no_delete:
            self.plugin.update_status(context.get_admin_context(),
                                      ldb.PoolV2,
                                      pool['pool']['id'],
                                      constants.ACTIVE)
            self._delete('pools', pool['pool']['id'])

    @contextlib.contextmanager
    def member(self, fmt=None, pool_id='pool1id', address='127.0.0.1',
               protocol_port=80, subnet=None, no_delete=False,
               **kwargs):
        if not fmt:
            fmt = self.fmt
        with test_db_plugin.optional_ctx(subnet, self.subnet) as tmp_subnet:
            res = self._create_member(fmt,
                                      pool_id=pool_id,
                                      address=address,
                                      protocol_port=protocol_port,
                                      subnet_id=tmp_subnet['subnet']['id'],
                                      **kwargs)
            if res.status_int >= webob.exc.HTTPClientError.code:
                raise webob.exc.HTTPClientError(
                    explanation=_("Unexpected error code: %s") % res.status_int
                )

            member = self.deserialize(fmt or self.fmt, res)
        yield member
        if not no_delete:
            self.plugin.update_status(context.get_admin_context(),
                                      ldb.MemberV2,
                                      member['member']['id'],
                                      constants.ACTIVE)
            del_req = self.new_delete_request(
                'pools',
                fmt=fmt,
                id=pool_id,
                subresource='members',
                sub_id=member['member']['id'])
            del_res = del_req.get_response(self.ext_api)
            self.assertEqual(del_res.status_int,
                             webob.exc.HTTPNoContent.code)

    @contextlib.contextmanager
    def healthmonitor(self, fmt=None, type='TCP', delay=1, timeout=1,
                      max_retries=1, no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_healthmonitor(fmt,
                                         type=type,
                                         delay=delay,
                                         timeout=timeout,
                                         max_retries=max_retries,
                                         **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(
                explanation=_("Unexpected error code: %s") % res.status_int
            )

        healthmonitor = self.deserialize(fmt or self.fmt, res)
        yield healthmonitor
        if not no_delete:
            self.plugin.update_status(context.get_admin_context(),
                                      ldb.HealthMonitorV2,
                                      healthmonitor['healthmonitor']['id'],
                                      constants.ACTIVE)
            self._delete('healthmonitors',
                         healthmonitor['healthmonitor']['id'])


class LbaasPluginDbTestCase(LbaasTestMixin,
                            test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, core_plugin=None, lb_plugin=None, lbaas_provider=None,
              ext_mgr=None):
        service_plugins = {'lb_plugin_name': DB_LB_PLUGIN_KLASS}
        if not lbaas_provider:
            lbaas_provider = (
                constants.LOADBALANCERv2 +
                ':lbaas:' + NOOP_DRIVER_KLASS + ':default')
        cfg.CONF.set_override('service_provider',
                              [lbaas_provider],
                              'service_providers')
        #force service type manager to reload configuration:
        sdb.ServiceTypeManager._instance = None

        super(LbaasPluginDbTestCase, self).setUp(
            ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )

        if not ext_mgr:
            self.plugin = loadbalancer_plugin.LoadBalancerPluginv2()
            ext_mgr = extensions.PluginAwareExtensionManager(
                extensions_path,
                {constants.LOADBALANCERv2: self.plugin}
            )
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)

        # get_lbaas_agent_patcher = mock.patch(
        #     'neutron.services.loadbalancer.agent_scheduler'
        #     '.LbaasAgentSchedulerDbMixin.get_lbaas_agent_hosting_pool')
        # mock_lbaas_agent = mock.MagicMock()
        # get_lbaas_agent_patcher.start().return_value = mock_lbaas_agent
        # mock_lbaas_agent.__getitem__.return_value = {'host': 'host'}

        self._subnet_id = _subnet_id


class TestLbaas(LbaasPluginDbTestCase):

    def test_create_loadbalancer(self, **extras):
        expected = {
            'name': 'vip1',
            'description': '',
            'admin_state_up': True,
            'status': 'ACTIVE',
            'tenant_id': self._tenant_id
        }

        expected.update(extras)

        with self.subnet() as subnet:
            expected['vip_subnet_id'] = subnet['subnet']['id']
            name = expected['name']

            with self.loadbalancer(name=name, subnet=subnet, **extras) as lb:
                for k in ('id', 'vip_address', 'vip_subnet_id'):
                    self.assertTrue(lb['loadbalancer'].get(k, None))

                actual = {k: v for k, v in lb['loadbalancer'].items()
                          if k in expected}
                self.assertEqual(actual, expected)
            return lb

    def test_create_loadbalancer_with_vip_address(self):
        self.test_create_loadbalancer(vip_address='10.0.0.7')

    def test_create_loadbalancer_with_vip_address_outside_subnet(self):
        with testtools.ExpectedException(webob.exc.HTTPClientError):
            self.test_create_loadbalancer(vip_address='9.9.9.9')

    def test_update_loadbalancer(self):
        name = 'new_loadbalancer'
        description = 'a crazy loadbalancer'
        expected_values = {'name': name,
                           'description': description,
                           'admin_state_up': False,
                           'status': constants.ACTIVE}
        with self.subnet() as subnet:
            expected_values['vip_subnet_id'] = subnet['subnet']['id']
            with self.loadbalancer(subnet=subnet) as loadbalancer:
                loadbalancer_id = loadbalancer['loadbalancer']['id']
                data = {'loadbalancer': {'name': name,
                                         'description': description,
                                         'admin_state_up': False}}
                req = self.new_update_request('loadbalancers', data,
                                              loadbalancer_id)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k in expected_values:
                    self.assertEqual(res['loadbalancer'][k],
                                     expected_values[k])

    def test_delete_loadbalancer(self):
        with self.subnet() as subnet:
            with self.loadbalancer(subnet=subnet,
                                   no_delete=True) as loadbalancer:
                loadbalancer_id = loadbalancer['loadbalancer']['id']
                req = self.new_delete_request('loadbalancers', loadbalancer_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_show_loadbalancer(self):
        name = 'lb_show'
        description = 'lb_show description'
        vip_address = '10.0.0.10'
        expected_values = {'name': name,
                           'description': description,
                           'vip_address': '10.0.0.10',
                           'admin_state_up': True,
                           'status': constants.ACTIVE}
        with self.subnet() as subnet:
            vip_subnet_id = subnet['subnet']['id']
            expected_values['vip_subnet_id'] = vip_subnet_id
            with self.loadbalancer(subnet=subnet, name=name,
                                   description=description,
                                   vip_address=vip_address) as lb:
                lb_id = lb['loadbalancer']['id']
                expected_values['id'] = lb_id
                req = self.new_show_request('loadbalancers', lb_id)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k in expected_values:
                    self.assertEqual(res['loadbalancer'][k],
                                     expected_values[k])

    def test_list_loadbalancers(self):
        name = 'lb_show'
        description = 'lb_show description'
        vip_address = '10.0.0.10'
        expected_values = {'name': name,
                           'description': description,
                           'vip_address': '10.0.0.10',
                           'admin_state_up': True,
                           'status': constants.ACTIVE}
        with self.subnet() as subnet:
            vip_subnet_id = subnet['subnet']['id']
            expected_values['vip_subnet_id'] = vip_subnet_id
            with self.loadbalancer(subnet=subnet, name=name,
                                   description=description,
                                   vip_address=vip_address) as lb:
                lb_id = lb['loadbalancer']['id']
                expected_values['id'] = lb_id
                req = self.new_list_request('loadbalancers')
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertEqual(len(res['loadbalancers']), 1)
                for k in expected_values:
                    self.assertEqual(res['loadbalancers'][0][k],
                                     expected_values[k])

    def test_list_loadbalancers_with_sort_emulated(self):
        with self.subnet() as subnet:
            with self.loadbalancer(subnet=subnet, name='lb1') as lb1, \
                    self.loadbalancer(subnet=subnet, name='lb2') as lb2, \
                    self.loadbalancer(subnet=subnet, name='lb3') as lb3:
                self._test_list_with_sort(
                    'loadbalancer',
                    (lb1, lb3, lb2),
                    [('name', 'desc')]
                )

    def test_list_loadbalancers_with_pagination_emulated(self):
        with self.subnet() as subnet:
            with self.loadbalancer(subnet=subnet, name='lb1') as lb1, \
                    self.loadbalancer(subnet=subnet, name='lb2') as lb2, \
                    self.loadbalancer(subnet=subnet, name='lb3') as lb3:
                self._test_list_with_pagination(
                    'loadbalancer',
                    (lb1, lb2, lb3),
                    ('name', 'asc'), 2, 2
                )

    def test_list_loadbalancers_with_pagination_reverse_emulated(self):
        with self.subnet() as subnet:
            with self.loadbalancer(subnet=subnet, name='lb1') as lb1, \
                    self.loadbalancer(subnet=subnet, name='lb2') as lb2, \
                    self.loadbalancer(subnet=subnet, name='lb3') as lb3:
                self._test_list_with_pagination_reverse(
                    'loadbalancer',
                    (lb1, lb2, lb3),
                    ('name', 'asc'), 2, 2
                )

    def test_get_loadbalancer_stats(self):
        expected_values = {'stats': {lb_const.STATS_TOTAL_CONNECTIONS: 0,
                                     lb_const.STATS_ACTIVE_CONNECTIONS: 0,
                                     lb_const.STATS_OUT_BYTES: 0,
                                     lb_const.STATS_IN_BYTES: 0}}
        with self.subnet() as subnet:
            with self.loadbalancer(subnet=subnet) as lb:
                lb_id = lb['loadbalancer']['id']
                req = self.new_show_request('loadbalancers', lb_id,
                                            subresource='stats')
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertEqual(res, expected_values)

    def test_create_listener(self, **extras):
        expected = {
            'protocol': 'HTTP',
            'protocol_port': 80,
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.listener() as listener:
            self.assertTrue(listener['listener'].get('id'))

            actual = {k: v for k, v in listener['listener'].items()
                      if k in expected}
            self.assertEqual(actual, expected)
        return listener

    def test_create_listener_same_port_same_load_balancer(self):
        with self.subnet() as subnet:
            with self.loadbalancer(subnet=subnet) as lb:
                lb_id = lb['loadbalancer']['id']
                with self.listener(loadbalancer_id=lb_id,
                                   protocol_port=80):
                    self._create_listener(self.fmt, 'HTTP', 80,
                                          loadbalancer_id=lb_id,
                                          expected_res_status=409)

    def test_create_listener_with_pool_protocol_mismatch(self):
        with self.pool(protocol='UDP') as pool:
            pool_id = pool['pool']['id']
            self._create_listener(self.fmt, 'TCP', 80,
                                  expected_res_status=409,
                                  default_pool_id=pool_id)

    def test_update_listener(self):
        name = 'new_listener'
        expected_values = {'name': name,
                           'protocol_port': 80,
                           'protocol': 'HTTP',
                           'connection_limit': 100,
                           'admin_state_up': False,
                           'tenant_id': self._tenant_id,
                           'status': constants.ACTIVE,
                           'loadbalancer_id': None,
                           'default_pool_id': None}

        with self.listener(name=name) as listener:
            listener_id = listener['listener']['id']
            data = {'listener': {'name': name,
                                 'connection_limit': 100,
                                 'admin_state_up': False}}
            req = self.new_update_request('listeners', data, listener_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k in expected_values:
                self.assertEqual(res['listener'][k], expected_values[k])

    def test_cannot_update_loadbalancer_id_on_listener_lb_id_exists(self):
        with self.subnet() as subnet:
            with self.loadbalancer(subnet=subnet) as lb1:
                lb1_id = lb1['loadbalancer']['id']
                with self.loadbalancer(subnet=subnet) as lb2:
                    lb2_id = lb2['loadbalancer']['id']
                    with self.listener(loadbalancer_id=lb1_id,
                                       protocol_port=80) as listener1:
                        listener_id = listener1['listener']['id']
                        self.assertRaises(
                            loadbalancerv2.LoadBalancerIDImmutable,
                            self.plugin.update_listener,
                            context.get_admin_context(),
                            listener_id,
                            {'listener': {'loadbalancer_id': lb2_id}})

    def test_update_loadbalancer_id_on_listener_lb_id_does_not_exist(self):
        with self.subnet() as subnet:
            with self.loadbalancer(subnet=subnet) as lb1:
                lb1_id = lb1['loadbalancer']['id']
                with self.listener(loadbalancer_id=lb1_id,
                                   protocol_port=80) as listener1:
                    listener_id = listener1['listener']['id']
                    ctx = context.get_admin_context()
                    import neutron.api.v2.attributes as attributes
                    self.plugin.update_listener(
                        ctx, listener_id,
                        {'listener': {'loadbalancer_id':
                                      attributes.ATTR_NOT_SPECIFIED}})
                    self.plugin.update_listener(
                        ctx, listener_id,
                        {'listener': {'loadbalancer_id': lb1_id}})

    def test_delete_listener(self):
        with self.listener(no_delete=True) as listener:
            listener_id = listener['listener']['id']
            req = self.new_delete_request('listeners', listener_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_show_listener(self):
        name = 'show_listener'
        expected_values = {'name': name,
                           'protocol_port': 80,
                           'protocol': 'HTTP',
                           'connection_limit': -1,
                           'admin_state_up': True,
                           'tenant_id': self._tenant_id,
                           'status': constants.ACTIVE,
                           'loadbalancer_id': None,
                           'default_pool_id': None}

        with self.listener(name=name) as listener:
            listener_id = listener['listener']['id']
            req = self.new_show_request('listeners', listener_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k in expected_values:
                self.assertEqual(res['listener'][k], expected_values[k])

    def test_list_listeners(self):
        name = 'list_listeners'
        expected_values = {'name': name,
                           'protocol_port': 80,
                           'protocol': 'HTTP',
                           'connection_limit': -1,
                           'admin_state_up': True,
                           'tenant_id': self._tenant_id,
                           'status': constants.ACTIVE,
                           'loadbalancer_id': None,
                           'default_pool_id': None}

        with self.listener(name=name) as listener:
            listener_id = listener['listener']['id']
            expected_values['id'] = listener_id
            req = self.new_list_request('listeners')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            listener_list = res['listeners']
            self.assertEqual(len(listener_list), 1)
            for k in expected_values:
                self.assertEqual(listener_list[0][k], expected_values[k])

    def test_list_listeners_with_sort_emulated(self):
        with self.listener(name='listener1', protocol_port=81) as listener1, \
                self.listener(name='listener2',
                              protocol_port=82) as listener2, \
                self.listener(name='listener3',
                              protocol_port=82) as listener3:
            self._test_list_with_sort(
                'listener',
                (listener1, listener3, listener2),
                [('protocol_port', 'asc'), ('name', 'desc')]
            )

    def test_list_listeners_with_pagination_emulated(self):
        with self.listener(name='listener1') as listener1, \
                self.listener(name='listener2') as listener2, \
                self.listener(name='listener3') as listener3:
            self._test_list_with_pagination(
                'listener',
                (listener1, listener2, listener3),
                ('name', 'desc'), 2, 2
            )

    def test_list_listeners_with_pagination_reverse_emulated(self):
        with self.listener(name='listener1') as listener1, \
                self.listener(name='listener2') as listener2, \
                self.listener(name='listener3') as listener3:
            self._test_list_with_pagination(
                'listener',
                (listener1, listener2, listener3),
                ('name', 'desc'), 2, 2
            )

    def test_create_listener_pool(self, **extras):
        with self.pool(protocol='HTTP') as pool:
            pool_id = pool['pool']['id']
            expected = {
                'protocol': 'HTTP',
                'protocol_port': 80,
                'admin_state_up': True,
                'tenant_id': self._tenant_id,
                'default_pool_id': pool_id,
                'status': constants.ACTIVE
            }

            expected.update(extras)

            with self.listener(default_pool_id=pool_id) as listener:
                self.assertTrue(listener['listener'].get('id'))

                actual = {k: v for k, v in listener['listener'].items()
                          if k in expected}
                self.assertEqual(expected, actual)
            return listener

    def test_update_listener_pool(self, **extras):
        with self.pool(protocol='HTTP') as pool:
            with self.pool(protocol='HTTP') as pool2:
                pool_id = pool['pool']['id']
                expected = {
                    'protocol': 'HTTP',
                    'protocol_port': 80,
                    'admin_state_up': True,
                    'tenant_id': self._tenant_id,
                    'default_pool_id': pool_id,
                    'status': constants.ACTIVE
                }

                expected.update(extras)

                with self.listener(default_pool_id=pool_id) as listener:
                    self.assertTrue(listener['listener'].get('id'))

                    actual = {k: v for k, v in listener['listener'].items()
                              if k in expected}
                    self.assertEqual(expected, actual)

                    data = {'listener': {
                        'default_pool_id': pool2['pool']['id']
                    }}

                    expected2 = {
                        'protocol': 'HTTP',
                        'protocol_port': 80,
                        'admin_state_up': True,
                        'tenant_id': self._tenant_id,
                        'default_pool_id': pool2['pool']['id'],
                        'status': constants.ACTIVE
                    }

                    req = self.new_update_request('listeners', data,
                                                  listener['listener']['id'],
                                                  fmt=self.fmt)
                    res = self.deserialize(
                        self.fmt, req.get_response(self.ext_api))
                    actual2 = {k: v for k, v in res['listener'].items()
                          if k in expected}
                    self.assertEqual(expected2, actual2)
                return listener

    def test_create_pool(self, **extras):
        expected = {
            'name': '',
            'description': '',
            'protocol': 'TCP',
            'lb_algorithm': 'ROUND_ROBIN',
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'healthmonitor_id': None,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.pool(**extras) as pool:
            self.assertTrue(pool['pool'].get('id'))

            actual = {k: v for k, v in pool['pool'].items()
                      if k in expected}
            self.assertEqual(actual, expected)
        return pool

    def test_show_pool(self, **extras):
        expected = {
            'name': '',
            'description': '',
            'protocol': 'TCP',
            'lb_algorithm': 'ROUND_ROBIN',
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'healthmonitor_id': None,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.pool() as pool:
            req = self.new_show_request('pools',
                                        pool['pool']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            actual = {k: v for k, v in res['pool'].items()
                      if k in expected}
            self.assertEqual(expected, actual)
        return pool

    def test_update_pool(self, **extras):
        expected = {
            'name': '',
            'description': '',
            'protocol': 'TCP',
            'lb_algorithm': 'LEAST_CONNECTIONS',
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'healthmonitor_id': None,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.pool() as pool:
            self.assertTrue(pool['pool'].get('id'))
            data = {'pool': {'lb_algorithm': 'LEAST_CONNECTIONS'}}
            req = self.new_update_request("pools", data,
                                          pool['pool']['id'],
                                          self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            actual = {k: v for k, v in res['pool'].items()
                      if k in expected}
            self.assertEqual(expected, actual)

        return pool

    def test_delete_pool(self):
        with self.pool(no_delete=True) as pool:
            ctx = context.get_admin_context()
            qry = ctx.session.query(ldb.PoolV2)
            qry = qry.filter_by(id=pool['pool']['id'])
            self.assertIsNotNone(qry.first())

            req = self.new_delete_request('pools',
                                          pool['pool']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            qry = ctx.session.query(ldb.PoolV2)
            qry = qry.filter_by(id=pool['pool']['id'])
            self.assertIsNone(qry.first())

    def test_create_pool_with_protocol_invalid(self):
        data = {'pool': {
            'name': '',
            'description': '',
            'protocol': 'BLANK',
            'lb_algorithm': 'LEAST_CONNECTIONS',
            'admin_state_up': True,
            'tenant_id': self._tenant_id
        }}
        req = self.new_create_request("pools", data,
                                      self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_pool_with_session_persistence(self):
        self.test_create_pool(session_persistence={'type': 'HTTP_COOKIE'})

    def test_create_pool_with_session_persistence_with_app_cookie(self):
        sp = {'type': 'APP_COOKIE', 'cookie_name': 'sessionId'}
        self.test_create_pool(session_persistence=sp)

    def test_create_pool_with_session_persistence_unsupported_type(self):
        with testtools.ExpectedException(webob.exc.HTTPClientError):
            self.test_create_pool(session_persistence={'type': 'UNSUPPORTED'})

    def test_create_pool_with_unnecessary_cookie_name(self):
        sp = {'type': "SOURCE_IP", 'cookie_name': 'sessionId'}
        with testtools.ExpectedException(webob.exc.HTTPClientError):
            self.test_create_pool(session_persistence=sp)

    def test_create_pool_with_session_persistence_without_cookie_name(self):
        sp = {'type': "APP_COOKIE"}
        with testtools.ExpectedException(webob.exc.HTTPClientError):
            self.test_create_pool(session_persistence=sp)

    def test_reset_session_persistence(self):
        name = 'pool4'
        sp = {'type': "HTTP_COOKIE"}

        update_info = {'pool': {'session_persistence': None}}

        with self.pool(name=name, session_persistence=sp) as pool:
            # Ensure that pool has been created properly
            self.assertEqual(pool['pool']['session_persistence'],
                             sp)

            # Try resetting session_persistence
            req = self.new_update_request('pools', update_info,
                                          pool['pool']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))

            self.assertIsNone(res['pool']['session_persistence'])

    def test_update_pool_with_protocol(self):
        with self.pool() as pool:
            data = {'pool': {'protocol': 'BLANK'}}
            req = self.new_update_request("pools", data, pool['pool']['id'],
                                          self.fmt)
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_list_pools_with_sort_emulated(self):
        with contextlib.nested(self.pool(protocol='HTTP'),
                               self.pool(protocol='HTTPS'),
                               self.pool(protocol='TCP')
                               ) as (p1, p2, p3):
            self._test_list_with_sort('pool', (p3, p2, p1),
                                      [('protocol', 'desc')])

    def test_list_pools_with_pagination_emulated(self):
        with contextlib.nested(self.pool(protocol='HTTP'),
                               self.pool(protocol='HTTPS'),
                               self.pool(protocol='TCP')
                               ) as (p1, p2, p3):
            self._test_list_with_pagination('pool',
                                            (p1, p2, p3),
                                            ('protocol', 'asc'), 2, 2)

    def test_list_pools_with_pagination_reverse_emulated(self):
        with contextlib.nested(self.pool(name='p1'),
                               self.pool(name='p2'),
                               self.pool(name='p3')
                               ) as (p1, p2, p3):
            self._test_list_with_pagination_reverse('pool',
                                                    (p1, p2, p3),
                                                    ('name', 'asc'), 2, 2)

    def test_create_member(self, **extras):
        expected = {
            'address': '127.0.0.1',
            'protocol_port': 80,
            'weight': 1,
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'status': constants.ACTIVE,
            'subnet_id': ''
        }

        expected.update(extras)

        with self.subnet() as subnet:
            expected['subnet_id'] = subnet['subnet']['id']
            with self.pool() as pool:
                pool_id = pool['pool']['id']
                with self.member(pool_id=pool_id,
                                 subnet=subnet) as member:
                    self.assertTrue(member['member'].get('id'))

                    actual = {k: v for k, v in member['member'].items()
                              if k in expected}
                    self.assertEqual(actual, expected)
        return member

    def test_create_member_with_existing_address_port_pool_combination(self):
        with self.subnet() as subnet:
            with self.pool() as pool:
                with self.member(pool_id=pool['pool']['id'],
                                 subnet=subnet) as member1:
                    member1 = member1['member']
                    member_data = {
                        'address': member1['address'],
                        'protocol_port': member1['protocol_port'],
                        'weight': 1,
                        'subnet_id': member1['subnet_id'],
                        'admin_state_up': True,
                        'tenant_id': member1['tenant_id']
                    }
                    self.assertRaises(
                        loadbalancerv2.MemberExists,
                        self.plugin.create_pool_member,
                        context.get_admin_context(),
                        {'member': member_data},
                        pool['pool']['id'])

    def test_update_member(self):
        with self.pool() as pool:
            keys = [('address', "127.0.0.1"),
                    ('tenant_id', self._tenant_id),
                    ('protocol_port', 80),
                    ('weight', 10),
                    ('admin_state_up', False),
                    ('status', constants.ACTIVE)]
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id) as member:
                req = self.new_show_request('pools',
                                            pool['pool']['id'],
                                            fmt=self.fmt)
                pool1_update = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                self.assertEqual(
                    len(pool1_update['pool']['members']), 1)

                self.assertEqual(
                    len(pool1_update['pool']['members']), 1)

                data = {'member': {'weight': 10,
                                   'admin_state_up': False}}
                req = self.new_update_request(
                    'pools',
                    data,
                    pool1_update['pool']['id'],
                    subresource='members',
                    sub_id=member['member']['id'])
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                for k, v in keys:
                    self.assertEqual(res['member'][k], v)

                req = self.new_show_request('pools',
                                            pool['pool']['id'],
                                            fmt=self.fmt)
                pool1_update = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )

                self.assertEqual(
                    len(pool1_update['pool']['members']), 1)

    def test_delete_member(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id,
                             no_delete=True) as member:
                req = self.new_delete_request('pools',
                                              pool_id,
                                              subresource='members',
                                              sub_id=member['member']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

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
            keys = [('address', "127.0.0.1"),
                    ('tenant_id', self._tenant_id),
                    ('protocol_port', 80),
                    ('weight', 1),
                    ('admin_state_up', True),
                    ('status', constants.ACTIVE)]
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id) as member:
                req = self.new_show_request('pools',
                                            pool_id,
                                            subresource='members',
                                            sub_id=member['member']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                for k, v in keys:
                    self.assertEqual(res['member'][k], v)

    def test_list_members(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id, protocol_port=81):
                req = self.new_list_request('pools', id=pool_id,
                                            subresource='members',
                                            fmt=self.fmt)
                res = req.get_response(self.ext_api)
                res = self.deserialize(self.fmt, res)
                self.assertEqual(len(res['members']), 1)

    def test_list_members_with_sort_emulated(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id, protocol_port=81) as m1, \
                    self.member(pool_id=pool_id, protocol_port=82) as m2, \
                    self.member(pool_id=pool_id, protocol_port=83) as m3:
                self._test_list_with_sort('pool', (m3, m2, m1),
                                          [('protocol_port', 'desc')],
                                          id=pool_id,
                                          subresource='member')

    def test_list_members_with_pagination_emulated(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id, protocol_port=81) as m1, \
                    self.member(pool_id=pool_id, protocol_port=82) as m2,\
                    self.member(pool_id=pool_id, protocol_port=83) as m3:
                self._test_list_with_pagination(
                    'pool', (m1, m2, m3), ('protocol_port', 'asc'), 2, 2,
                    id=pool_id, subresource='member'
                )

    def test_list_members_with_pagination_reverse_emulated(self):
        with self.pool() as pool:
            pool_id = pool['pool']['id']
            with self.member(pool_id=pool_id, protocol_port=81) as m1, \
                    self.member(pool_id=pool_id, protocol_port=82) as m2, \
                    self.member(pool_id=pool_id, protocol_port=83) as m3:
                self._test_list_with_pagination_reverse(
                    'pool', (m1, m2, m3), ('protocol_port', 'asc'), 2, 2,
                    id=pool_id, subresource='member'
                )

    def test_create_healthmonitor(self, **extras):
        expected = {
            'type': 'TCP',
            'delay': 1,
            'timeout': 1,
            'max_retries': 1,
            'http_method': 'GET',
            'url_path': '/',
            'expected_codes': '200',
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.healthmonitor() as healthmonitor:
            self.assertTrue(healthmonitor['healthmonitor'].get('id'))

            actual = {k: v for k, v in healthmonitor['healthmonitor'].items()
                      if k in expected}
            self.assertEqual(expected, actual)
        return healthmonitor

    def test_show_healthmonitor(self, **extras):
        expected = {
            'type': 'TCP',
            'delay': 1,
            'timeout': 1,
            'max_retries': 1,
            'http_method': 'GET',
            'url_path': '/',
            'expected_codes': '200',
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.healthmonitor() as healthmonitor:
            req = self.new_show_request('healthmonitors',
                                        healthmonitor['healthmonitor']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            actual = {k: v for k, v in res['healthmonitor'].items()
                      if k in expected}
            self.assertEqual(expected, actual)

        return healthmonitor

    def test_update_healthmonitor(self, **extras):
        expected = {
            'type': 'TCP',
            'delay': 30,
            'timeout': 10,
            'max_retries': 4,
            'http_method': 'GET',
            'url_path': '/index.html',
            'expected_codes': '200,404',
            'admin_state_up': True,
            'tenant_id': self._tenant_id,
            'status': constants.ACTIVE
        }

        expected.update(extras)

        with self.healthmonitor() as healthmonitor:
            data = {'healthmonitor': {'delay': 30,
                                      'timeout': 10,
                                      'max_retries': 4,
                                      'expected_codes': '200,404',
                                      'url_path': '/index.html'}}
            req = self.new_update_request("healthmonitors", data,
                                          healthmonitor['healthmonitor']['id'],
                                          self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            actual = {k: v for k, v in res['healthmonitor'].items()
                      if k in expected}
            self.assertEqual(expected, actual)

        return healthmonitor

    def test_delete_healthmonitor(self):
        with self.healthmonitor(no_delete=True) as monitor:
            ctx = context.get_admin_context()
            qry = ctx.session.query(ldb.HealthMonitorV2)
            qry = qry.filter_by(id=monitor['healthmonitor']['id'])
            self.assertIsNotNone(qry.first())

            req = self.new_delete_request('healthmonitors',
                                          monitor['healthmonitor']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            qry = ctx.session.query(ldb.HealthMonitorV2)
            qry = qry.filter_by(id=monitor['healthmonitor']['id'])
            self.assertIsNone(qry.first())

    def test_create_health_monitor_with_timeout_invalid(self):
        data = {'healthmonitor': {'type': 'HTTP',
                                  'delay': 1,
                                  'timeout': -1,
                                  'max_retries': 2,
                                  'admin_state_up': True,
                                  'tenant_id': self._tenant_id}}
        req = self.new_create_request('healthmonitors', data, self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_health_monitor_with_timeout_invalid(self):
        with self.healthmonitor() as monitor:
            data = {'healthmonitor': {'delay': 10,
                                      'timeout': -1,
                                      'max_retries': 2,
                                      'admin_state_up': False}}
            req = self.new_update_request("healthmonitors",
                                          data,
                                          monitor['healthmonitor']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_health_monitor_with_delay_invalid(self):
        data = {'healthmonitor': {'type': 'HTTP',
                                  'delay': -1,
                                  'timeout': 1,
                                  'max_retries': 2,
                                  'admin_state_up': True,
                                  'tenant_id': self._tenant_id}}
        req = self.new_create_request('healthmonitors', data, self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_health_monitor_with_delay_invalid(self):
        with self.healthmonitor() as monitor:
            data = {'healthmonitor': {'delay': -1,
                                      'timeout': 1,
                                      'max_retries': 2,
                                      'admin_state_up': False}}
            req = self.new_update_request("healthmonitors",
                                          data,
                                          monitor['healthmonitor']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_health_monitor_with_max_retries_invalid(self):
        data = {'healthmonitor': {'type': 'HTTP',
                                  'delay': 1,
                                  'timeout': 1,
                                  'max_retries': 20,
                                  'admin_state_up': True,
                                  'tenant_id': self._tenant_id}}
        req = self.new_create_request('healthmonitors', data, self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_health_monitor_with_max_retries_invalid(self):
        with self.healthmonitor() as monitor:
            data = {'healthmonitor': {'delay': 1,
                                      'timeout': 1,
                                      'max_retries': 20,
                                      'admin_state_up': False}}
            req = self.new_update_request("healthmonitors",
                                          data,
                                          monitor['healthmonitor']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_health_monitor_with_http_method_invalid(self):
        data = {'healthmonitor': {'type': 1,
                                  'delay': 1,
                                  'timeout': 1,
                                  'max_retries': 2,
                                  'admin_state_up': True,
                                  'tenant_id': self._tenant_id}}
        req = self.new_create_request('healthmonitors', data, self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_health_monitor_with_http_method_invalid(self):
        with self.healthmonitor() as monitor:
            data = {'healthmonitor': {'type': 1,
                                      'delay': 1,
                                      'timeout': 1,
                                      'max_retries': 2,
                                      'admin_state_up': False}}
            req = self.new_update_request("healthmonitors",
                                          data,
                                          monitor['healthmonitor']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_health_monitor_with_url_path_invalid(self):
        data = {'healthmonitor': {'type': 'HTTP',
                                  'url_path': 1,
                                  'delay': 1,
                                  'timeout': 1,
                                  'max_retries': 2,
                                  'admin_state_up': True,
                                  'tenant_id': self._tenant_id}}
        req = self.new_create_request('healthmonitors', data, self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_health_monitor_with_url_path_invalid(self):
        with self.healthmonitor() as monitor:
            data = {'healthmonitor': {'url_path': 1,
                                      'delay': 1,
                                      'timeout': 1,
                                      'max_retries': 2,
                                      'admin_state_up': False}}
            req = self.new_update_request("healthmonitors",
                                          data,
                                          monitor['healthmonitor']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_add_healthmonitor_to_pool(self):
        with self.healthmonitor(type='HTTP') as monitor:
            hm_id = monitor['healthmonitor']['id']
            data = {'pool': {'protocol': 'HTTP',
                             'healthmonitor_id': hm_id,
                             'lb_algorithm': 'ROUND_ROBIN',
                             'tenant_id': self._tenant_id}
                    }
            req = self.new_create_request(
                'pools',
                data,
                fmt=self.fmt,)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

            ctx = context.get_admin_context()

            # check if we actually have corresponding Pool associations
            qry = ctx.session.query(ldb.PoolV2)
            qry = qry.filter_by(
                healthmonitor_id=monitor['healthmonitor']['id'])
            self.assertTrue(qry.all())

    def test_add_shared_healthmonitor_to_pool(self):
        with self.healthmonitor(type='HTTP') as monitor:
            data = {'pool': {'protocol': 'HTTP',
                             'healthmonitor_id':
                                 monitor['healthmonitor']['id'],
                             'lb_algorithm': 'ROUND_ROBIN',
                             'tenant_id': self._tenant_id}
                    }
            req = self.new_create_request(
                'pools',
                data,
                fmt=self.fmt,)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

            ctx = context.get_admin_context()

            # check if we actually have corresponding Pool associations
            qry = ctx.session.query(ldb.PoolV2)
            qry = qry.filter_by(
                healthmonitor_id=monitor['healthmonitor']['id'])
            self.assertTrue(qry.all())

            req = self.new_create_request(
                'pools',
                data,
                fmt=self.fmt,)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

    def test_update_healthmonitor_to_pool(self):
        with self.healthmonitor(type='HTTP') as monitor:
            hm_id = monitor['healthmonitor']['id']
            with self.pool() as pool:
                data = {'pool': {'healthmonitor_id': hm_id}}
                req = self.new_update_request(
                    'pools',
                    data,
                    pool['pool']['id'],
                    fmt=self.fmt,)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

                ctx = context.get_admin_context()

                # check if we actually have corresponding Pool associations
                qry = ctx.session.query(ldb.PoolV2)
                qry = qry.filter_by(
                    healthmonitor_id=monitor['healthmonitor']['id'])
                self.assertTrue(qry.all())

    def test_delete_healthmonitor_with_associations_allowed(self):
        with self.healthmonitor(type='HTTP', no_delete=True) as monitor:
            hm_id = monitor['healthmonitor']['id']
            data = {'pool': {'protocol': 'HTTP',
                             'healthmonitor_id': hm_id,
                             'lb_algorithm': 'ROUND_ROBIN',
                             'tenant_id': self._tenant_id}
                    }
            req = self.new_create_request(
                'pools',
                data,
                fmt=self.fmt,)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

            ctx = context.get_admin_context()

            # check if we actually have corresponding Pool associations
            qry = ctx.session.query(ldb.PoolV2)
            qry = qry.filter_by(
                healthmonitor_id=monitor['healthmonitor']['id'])
            self.assertTrue(qry.all())
            # try to delete the HealthMonitor instance
            req = self.new_delete_request('healthmonitors',
                                          monitor['healthmonitor']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

            qry = ctx.session.query(ldb.HealthMonitorV2)
            qry = qry.filter_by(id=monitor['healthmonitor']['id'])
            self.assertIsNone(qry.first())
            # check if all corresponding Pool associations are deleted
            qry = ctx.session.query(ldb.PoolV2)
            qry = qry.filter_by(
                healthmonitor_id=monitor['healthmonitor']['id'])
            self.assertEqual([], qry.all())

    def test_add_healthmonitor_to_pool_invalid_monitor_id(self):
        data = {'pool': {'protocol': 'HTTP',
                         'healthmonitor_id': 'notanid',
                         'lb_algorithm': 'ROUND_ROBIN',
                         'tenant_id': self._tenant_id}
                }
        req = self.new_create_request(
            'pools',
            data,
            fmt=self.fmt,)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_update_healthmonitor_to_pool_invalid_monitor_id(self):
        with self.pool() as pool:
            data = {'pool': {'healthmonitor_id': 'notanid'}}
            req = self.new_update_request(
                'pools',
                data,
                pool['pool']['id'],
                fmt=self.fmt,)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)


class TestLbaasXML(TestLbaas):
    fmt = 'xml'
