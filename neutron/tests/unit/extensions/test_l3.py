# Copyright 2012 VMware, Inc.
# All rights reserved.
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
import copy

import mock
import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
from oslo_utils import uuidutils
from webob import exc

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.api.v2 import attributes
from neutron.callbacks import exceptions
from neutron.callbacks import registry
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import common_db_mixin
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import l3_dvr_db
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants as service_constants
from neutron.tests import base
from neutron.tests.common import helpers
from neutron.tests import fake_notifier
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import base as test_extensions_base
from neutron.tests.unit.extensions import test_agent

LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


class L3TestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            l3.RESOURCE_ATTRIBUTE_MAP)
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3NatExtensionTestCase(test_extensions_base.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(L3NatExtensionTestCase, self).setUp()
        self._setUpExtension(
            'neutron.extensions.l3.RouterPluginBase', None,
            l3.RESOURCE_ATTRIBUTE_MAP, l3.L3, '',
            allow_pagination=True, allow_sorting=True,
            supported_extension_aliases=['router'],
            use_quota=True)

    def test_router_create(self):
        router_id = _uuid()
        data = {'router': {'name': 'router1', 'admin_state_up': True,
                           'tenant_id': _uuid(),
                           'external_gateway_info': None}}
        return_value = copy.deepcopy(data['router'])
        return_value.update({'status': "ACTIVE", 'id': router_id})

        instance = self.plugin.return_value
        instance.create_router.return_value = return_value
        instance.get_routers_count.return_value = 0
        res = self.api.post(_get_path('routers', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_router.assert_called_with(mock.ANY,
                                                  router=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('router', res)
        router = res['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], True)

    def test_router_list(self):
        router_id = _uuid()
        return_value = [{'name': 'router1', 'admin_state_up': True,
                         'tenant_id': _uuid(), 'id': router_id}]

        instance = self.plugin.return_value
        instance.get_routers.return_value = return_value

        res = self.api.get(_get_path('routers', fmt=self.fmt))

        instance.get_routers.assert_called_with(mock.ANY, fields=mock.ANY,
                                                filters=mock.ANY,
                                                sorts=mock.ANY,
                                                limit=mock.ANY,
                                                marker=mock.ANY,
                                                page_reverse=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('routers', res)
        self.assertEqual(1, len(res['routers']))
        self.assertEqual(router_id, res['routers'][0]['id'])

    def test_router_update(self):
        router_id = _uuid()
        update_data = {'router': {'admin_state_up': False}}
        return_value = {'name': 'router1', 'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE", 'id': router_id}

        instance = self.plugin.return_value
        instance.update_router.return_value = return_value

        res = self.api.put(_get_path('routers', id=router_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_router.assert_called_with(mock.ANY, router_id,
                                                  router=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('router', res)
        router = res['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], False)

    def test_router_get(self):
        router_id = _uuid()
        return_value = {'name': 'router1', 'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': "ACTIVE", 'id': router_id}

        instance = self.plugin.return_value
        instance.get_router.return_value = return_value

        res = self.api.get(_get_path('routers', id=router_id,
                                     fmt=self.fmt))

        instance.get_router.assert_called_with(mock.ANY, router_id,
                                               fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('router', res)
        router = res['router']
        self.assertEqual(router['id'], router_id)
        self.assertEqual(router['status'], "ACTIVE")
        self.assertEqual(router['admin_state_up'], False)

    def test_router_delete(self):
        router_id = _uuid()

        res = self.api.delete(_get_path('routers', id=router_id))

        instance = self.plugin.return_value
        instance.delete_router.assert_called_with(mock.ANY, router_id)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

    def test_router_add_interface(self):
        router_id = _uuid()
        subnet_id = _uuid()
        port_id = _uuid()

        interface_data = {'subnet_id': subnet_id}
        return_value = copy.deepcopy(interface_data)
        return_value['port_id'] = port_id

        instance = self.plugin.return_value
        instance.add_router_interface.return_value = return_value

        path = _get_path('routers', id=router_id,
                         action="add_router_interface",
                         fmt=self.fmt)
        res = self.api.put(path, self.serialize(interface_data))

        instance.add_router_interface.assert_called_with(mock.ANY, router_id,
                                                         interface_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('port_id', res)
        self.assertEqual(res['port_id'], port_id)
        self.assertEqual(res['subnet_id'], subnet_id)


# This base plugin class is for tests.
class TestL3NatBasePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                          external_net_db.External_net_db_mixin):

    __native_pagination_support = True
    __native_sorting_support = True

    def create_network(self, context, network):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(TestL3NatBasePlugin, self).create_network(context,
                                                                  network)
            self._process_l3_create(context, net, network['network'])
        return net

    def update_network(self, context, id, network):

        session = context.session
        with session.begin(subtransactions=True):
            net = super(TestL3NatBasePlugin, self).update_network(context, id,
                                                                  network)
            self._process_l3_update(context, net, network['network'])
        return net

    def delete_network(self, context, id):
        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, id)
            super(TestL3NatBasePlugin, self).delete_network(context, id)

    def delete_port(self, context, id, l3_port_check=True):
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if plugin:
            if l3_port_check:
                plugin.prevent_l3_port_deletion(context, id)
            plugin.disassociate_floatingips(context, id)
        return super(TestL3NatBasePlugin, self).delete_port(context, id)


# This plugin class is for tests with plugin that integrates L3.
class TestL3NatIntPlugin(TestL3NatBasePlugin,
                         l3_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["external-net", "router"]


# This plugin class is for tests with plugin that integrates L3 and L3 agent
# scheduling.
class TestL3NatIntAgentSchedulingPlugin(TestL3NatIntPlugin,
                                        l3_agentschedulers_db.
                                        L3AgentSchedulerDbMixin):

    supported_extension_aliases = ["external-net", "router",
                                   "l3_agent_scheduler"]
    router_scheduler = importutils.import_object(
        cfg.CONF.router_scheduler_driver)


# This plugin class is for tests with plugin not supporting L3.
class TestNoL3NatPlugin(TestL3NatBasePlugin):

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["external-net"]


# A L3 routing service plugin class for tests with plugins that
# delegate away L3 routing functionality
class TestL3NatServicePlugin(common_db_mixin.CommonDbMixin,
                             l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                             l3_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["router"]

    def get_plugin_type(self):
        return service_constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        return "L3 Routing Service Plugin for testing"


# A L3 routing with L3 agent scheduling service plugin class for tests with
# plugins that delegate away L3 routing functionality
class TestL3NatAgentSchedulingServicePlugin(TestL3NatServicePlugin,
                                            l3_agentschedulers_db.
                                            L3AgentSchedulerDbMixin):

    supported_extension_aliases = ["router", "l3_agent_scheduler"]

    def __init__(self):
        super(TestL3NatAgentSchedulingServicePlugin, self).__init__()
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        self.agent_notifiers.update(
            {l3_constants.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})


class L3NatTestCaseMixin(object):

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if kwargs.get(arg):
                data['router'][arg] = kwargs[arg]
        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _make_router(self, fmt, tenant_id, name=None, admin_state_up=None,
                     external_gateway_info=None, set_context=False,
                     arg_list=None, **kwargs):
        if external_gateway_info:
            arg_list = ('external_gateway_info', ) + (arg_list or ())
        res = self._create_router(fmt, tenant_id, name,
                                  admin_state_up, set_context,
                                  arg_list=arg_list,
                                  external_gateway_info=external_gateway_info,
                                  **kwargs)
        return self.deserialize(fmt, res)

    def _add_external_gateway_to_router(self, router_id, network_id,
                                        expected_code=exc.HTTPOk.code,
                                        neutron_context=None, ext_ips=[]):
        body = {'router':
                {'external_gateway_info': {'network_id': network_id}}}
        if ext_ips:
            body['router']['external_gateway_info'][
                'external_fixed_ips'] = ext_ips
        return self._update('routers', router_id, body,
                            expected_code=expected_code,
                            neutron_context=neutron_context)

    def _remove_external_gateway_from_router(self, router_id, network_id,
                                             expected_code=exc.HTTPOk.code,
                                             external_gw_info=None):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                        external_gw_info}},
                            expected_code=expected_code)

    def _router_interface_action(self, action, router_id, subnet_id, port_id,
                                 expected_code=exc.HTTPOk.code,
                                 expected_body=None,
                                 tenant_id=None,
                                 msg=None):
        interface_data = {}
        if subnet_id:
            interface_data.update({'subnet_id': subnet_id})
        if port_id:
            interface_data.update({'port_id': port_id})

        req = self.new_action_request('routers', interface_data, router_id,
                                      "%s_router_interface" % action)
        # if tenant_id was specified, create a tenant context for this request
        if tenant_id:
            req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code, msg)
        response = self.deserialize(self.fmt, res)
        if expected_body:
            self.assertEqual(response, expected_body, msg)
        return response

    @contextlib.contextmanager
    def router(self, name='router1', admin_state_up=True,
               fmt=None, tenant_id=_uuid(),
               external_gateway_info=None, set_context=False,
               **kwargs):
        router = self._make_router(fmt or self.fmt, tenant_id, name,
                                   admin_state_up, external_gateway_info,
                                   set_context, **kwargs)
        yield router

    def _set_net_external(self, net_id):
        self._update('networks', net_id,
                     {'network': {external_net.EXTERNAL: True}})

    def _create_floatingip(self, fmt, network_id, port_id=None,
                           fixed_ip=None, set_context=False,
                           floating_ip=None):
        data = {'floatingip': {'floating_network_id': network_id,
                               'tenant_id': self._tenant_id}}
        if port_id:
            data['floatingip']['port_id'] = port_id
            if fixed_ip:
                data['floatingip']['fixed_ip_address'] = fixed_ip

        if floating_ip:
            data['floatingip']['floating_ip_address'] = floating_ip

        floatingip_req = self.new_create_request('floatingips', data, fmt)
        if set_context and self._tenant_id:
            # create a specific auth context for this request
            floatingip_req.environ['neutron.context'] = context.Context(
                '', self._tenant_id)
        return floatingip_req.get_response(self.ext_api)

    def _make_floatingip(self, fmt, network_id, port_id=None,
                         fixed_ip=None, set_context=False, floating_ip=None,
                         http_status=exc.HTTPCreated.code):
        res = self._create_floatingip(fmt, network_id, port_id,
                                      fixed_ip, set_context, floating_ip)
        self.assertEqual(res.status_int, http_status)
        return self.deserialize(fmt, res)

    def _validate_floating_ip(self, fip):
        body = self._list('floatingips')
        self.assertEqual(len(body['floatingips']), 1)
        self.assertEqual(body['floatingips'][0]['id'],
                         fip['floatingip']['id'])

        body = self._show('floatingips', fip['floatingip']['id'])
        self.assertEqual(body['floatingip']['id'],
                         fip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_with_assoc(self, port_id=None, fmt=None, fixed_ip=None,
                              set_context=False):
        with self.subnet(cidr='11.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            private_port = None
            if port_id:
                private_port = self._show('ports', port_id)
            with test_db_base_plugin_v2.optional_ctx(private_port,
                                             self.port) as private_port:
                with self.router() as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    floatingip = None

                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action(
                        'add', r['router']['id'],
                        private_sub['subnet']['id'], None)

                    floatingip = self._make_floatingip(
                        fmt or self.fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'],
                        fixed_ip=fixed_ip,
                        set_context=set_context)
                    yield floatingip

                    if floatingip:
                        self._delete('floatingips',
                                     floatingip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_no_assoc_with_public_sub(
        self, private_sub, fmt=None, set_context=False, public_sub=None):
        self._set_net_external(public_sub['subnet']['network_id'])
        with self.router() as r:
            floatingip = None

            self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'])
            self._router_interface_action('add', r['router']['id'],
                                          private_sub['subnet']['id'],
                                          None)

            floatingip = self._make_floatingip(
                fmt or self.fmt,
                public_sub['subnet']['network_id'],
                set_context=set_context)
            yield floatingip, r

            if floatingip:
                self._delete('floatingips',
                             floatingip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_no_assoc(self, private_sub, fmt=None, set_context=False):
        with self.subnet(cidr='12.0.0.0/24') as public_sub:
            with self.floatingip_no_assoc_with_public_sub(
                private_sub, fmt, set_context, public_sub) as (f, r):
                # Yield only the floating ip object
                yield f


class ExtraAttributesMixinTestCase(base.BaseTestCase):

    def setUp(self):
        super(ExtraAttributesMixinTestCase, self).setUp()
        self.mixin = l3_attrs_db.ExtraAttributesMixin()

    def _test__extend_extra_router_dict(
        self, extra_attributes, attributes, expected_attributes):
        self.mixin._extend_extra_router_dict(
            attributes, {'extra_attributes': extra_attributes})
        self.assertEqual(expected_attributes, attributes)

    def test__extend_extra_router_dict_string_default(self):
        self.mixin.extra_attributes = [{
            'name': "foo_key",
            'default': 'foo_default'
        }]
        extension_attributes = {'foo_key': 'my_fancy_value'}
        self._test__extend_extra_router_dict(
            extension_attributes, {}, extension_attributes)

    def test__extend_extra_router_dict_booleans_false_default(self):
        self.mixin.extra_attributes = [{
            'name': "foo_key",
            'default': False
        }]
        extension_attributes = {'foo_key': True}
        self._test__extend_extra_router_dict(
            extension_attributes, {}, extension_attributes)

    def test__extend_extra_router_dict_booleans_true_default(self):
        self.mixin.extra_attributes = [{
            'name': "foo_key",
            'default': True
        }]
        # Test that the default is overridden
        extension_attributes = {'foo_key': False}
        self._test__extend_extra_router_dict(
            extension_attributes, {}, extension_attributes)

    def test__extend_extra_router_dict_no_extension_attributes(self):
        self.mixin.extra_attributes = [{
            'name': "foo_key",
            'default': 'foo_value'
        }]
        self._test__extend_extra_router_dict({}, {}, {'foo_key': 'foo_value'})

    def test__extend_extra_router_dict_none_extension_attributes(self):
        self._test__extend_extra_router_dict(None, {}, {})


class L3NatTestCaseBase(L3NatTestCaseMixin):

    def test_router_create(self):
        name = 'router1'
        tenant_id = _uuid()
        expected_value = [('name', name), ('tenant_id', tenant_id),
                          ('admin_state_up', True), ('status', 'ACTIVE'),
                          ('external_gateway_info', None)]
        with self.router(name='router1', admin_state_up=True,
                         tenant_id=tenant_id) as router:
            for k, v in expected_value:
                self.assertEqual(router['router'][k], v)

    def test_router_create_call_extensions(self):
        self.extension_called = False

        def _extend_router_dict_test_attr(*args, **kwargs):
            self.extension_called = True

        db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
            l3.ROUTERS, [_extend_router_dict_test_attr])
        self.assertFalse(self.extension_called)
        with self.router():
            self.assertTrue(self.extension_called)

    def test_router_create_with_gwinfo(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            data = {'router': {'tenant_id': _uuid()}}
            data['router']['name'] = 'router1'
            data['router']['external_gateway_info'] = {
                'network_id': s['subnet']['network_id']}
            router_req = self.new_create_request('routers', data, self.fmt)
            res = router_req.get_response(self.ext_api)
            router = self.deserialize(self.fmt, res)
            self.assertEqual(
                s['subnet']['network_id'],
                router['router']['external_gateway_info']['network_id'])

    def test_router_create_with_gwinfo_ext_ip(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            ext_info = {
                'network_id': s['subnet']['network_id'],
                'external_fixed_ips': [{'ip_address': '10.0.0.99'}]
            }
            res = self._create_router(
                self.fmt, _uuid(), arg_list=('external_gateway_info',),
                external_gateway_info=ext_info
            )
            router = self.deserialize(self.fmt, res)
            self.assertEqual(
                [{'ip_address': '10.0.0.99', 'subnet_id': s['subnet']['id']}],
                router['router']['external_gateway_info'][
                    'external_fixed_ips'])

    def test_router_create_with_gwinfo_ext_ip_subnet(self):
        with self.network() as n:
            with self.subnet(network=n) as v1,\
                    self.subnet(network=n, cidr='1.0.0.0/24') as v2,\
                    self.subnet(network=n, cidr='2.0.0.0/24') as v3:
                subnets = (v1, v2, v3)
                self._set_net_external(n['network']['id'])
                for s in subnets:
                    ext_info = {
                        'network_id': n['network']['id'],
                        'external_fixed_ips': [
                            {'subnet_id': s['subnet']['id']}]
                    }
                    res = self._create_router(
                        self.fmt, _uuid(), arg_list=('external_gateway_info',),
                        external_gateway_info=ext_info
                    )
                    router = self.deserialize(self.fmt, res)
                    ext_ips = router['router']['external_gateway_info'][
                        'external_fixed_ips']

                    self.assertEqual(
                        [{'subnet_id': s['subnet']['id'],
                          'ip_address': mock.ANY}], ext_ips)

    def test_router_create_with_gwinfo_ext_ip_non_admin(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            ext_info = {
                'network_id': s['subnet']['network_id'],
                'external_fixed_ips': [{'ip_address': '10.0.0.99'}]
            }
            res = self._create_router(
                self.fmt, _uuid(), arg_list=('external_gateway_info',),
                set_context=True, external_gateway_info=ext_info
            )
            self.assertEqual(res.status_int, exc.HTTPForbidden.code)

    def test_router_list(self):
        with self.router() as v1, self.router() as v2, self.router() as v3:
            routers = (v1, v2, v3)
            self._test_list_resources('router', routers)

    def test_router_list_with_parameters(self):
        with self.router(name='router1') as router1,\
                self.router(name='router2') as router2:
            query_params = 'name=router1'
            self._test_list_resources('router', [router1],
                                      query_params=query_params)
            query_params = 'name=router2'
            self._test_list_resources('router', [router2],
                                      query_params=query_params)
            query_params = 'name=router3'
            self._test_list_resources('router', [],
                                      query_params=query_params)

    def test_router_list_with_sort(self):
        with self.router(name='router1') as router1,\
                self.router(name='router2') as router2,\
                self.router(name='router3') as router3:
            self._test_list_with_sort('router', (router3, router2, router1),
                                      [('name', 'desc')])

    def test_router_list_with_pagination(self):
        with self.router(name='router1') as router1,\
                self.router(name='router2') as router2,\
                self.router(name='router3') as router3:
            self._test_list_with_pagination('router',
                                            (router1, router2, router3),
                                            ('name', 'asc'), 2, 2)

    def test_router_list_with_pagination_reverse(self):
        with self.router(name='router1') as router1,\
                self.router(name='router2') as router2,\
                self.router(name='router3') as router3:
            self._test_list_with_pagination_reverse('router',
                                                    (router1, router2,
                                                     router3),
                                                    ('name', 'asc'), 2, 2)

    def test_router_update(self):
        rname1 = "yourrouter"
        rname2 = "nachorouter"
        with self.router(name=rname1) as r:
            body = self._show('routers', r['router']['id'])
            self.assertEqual(body['router']['name'], rname1)

            body = self._update('routers', r['router']['id'],
                                {'router': {'name': rname2}})

            body = self._show('routers', r['router']['id'])
            self.assertEqual(body['router']['name'], rname2)

    def test_router_update_gateway(self):
        with self.router() as r:
            with self.subnet() as s1:
                with self.subnet() as s2:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEqual(net_id, s1['subnet']['network_id'])
                    self._set_net_external(s2['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEqual(net_id, s2['subnet']['network_id'])
                    # Validate that we can clear the gateway with
                    # an empty dict, in any other case, we fall back
                    # on None as default value
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        s2['subnet']['network_id'],
                        external_gw_info={})

    def test_router_update_gateway_with_external_ip_used_by_gw(self):
        with self.router() as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'],
                    ext_ips=[{'ip_address': s['subnet']['gateway_ip']}],
                    expected_code=exc.HTTPBadRequest.code)

    def test_router_update_gateway_with_invalid_external_ip(self):
        with self.router() as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'],
                    ext_ips=[{'ip_address': '99.99.99.99'}],
                    expected_code=exc.HTTPBadRequest.code)

    def test_router_update_gateway_with_invalid_external_subnet(self):
        with self.subnet() as s1,\
                self.subnet(cidr='1.0.0.0/24') as s2,\
                self.router() as r:
            self._set_net_external(s1['subnet']['network_id'])
            self._add_external_gateway_to_router(
                r['router']['id'],
                s1['subnet']['network_id'],
                # this subnet is not on the same network so this should fail
                ext_ips=[{'subnet_id': s2['subnet']['id']}],
                expected_code=exc.HTTPBadRequest.code)

    def test_router_update_gateway_with_different_external_subnet(self):
        with self.network() as n:
            with self.subnet(network=n) as s1,\
                    self.subnet(network=n, cidr='1.0.0.0/24') as s2,\
                    self.router() as r:
                self._set_net_external(n['network']['id'])
                res1 = self._add_external_gateway_to_router(
                    r['router']['id'],
                    n['network']['id'],
                    ext_ips=[{'subnet_id': s1['subnet']['id']}])
                res2 = self._add_external_gateway_to_router(
                    r['router']['id'],
                    n['network']['id'],
                    ext_ips=[{'subnet_id': s2['subnet']['id']}])
        fip1 = res1['router']['external_gateway_info']['external_fixed_ips'][0]
        fip2 = res2['router']['external_gateway_info']['external_fixed_ips'][0]
        self.assertEqual(s1['subnet']['id'], fip1['subnet_id'])
        self.assertEqual(s2['subnet']['id'], fip2['subnet_id'])
        self.assertNotEqual(fip1['subnet_id'], fip2['subnet_id'])
        self.assertNotEqual(fip1['ip_address'], fip2['ip_address'])

    def test_router_update_gateway_with_existed_floatingip(self):
        with self.subnet() as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with self.floatingip_with_assoc() as fip:
                self._add_external_gateway_to_router(
                    fip['floatingip']['router_id'],
                    subnet['subnet']['network_id'],
                    expected_code=exc.HTTPConflict.code)

    def test_router_update_gateway_to_empty_with_existed_floatingip(self):
        with self.floatingip_with_assoc() as fip:
            self._remove_external_gateway_from_router(
                fip['floatingip']['router_id'], None,
                expected_code=exc.HTTPConflict.code)

    def test_router_update_gateway_add_multiple_prefixes_ipv6(self):
        with self.network() as n:
            with self.subnet(network=n) as s1, \
                self.subnet(network=n, ip_version=6, cidr='2001:db8::/32') \
                as s2, (self.router()) as r:
                self._set_net_external(n['network']['id'])
                res1 = self._add_external_gateway_to_router(
                        r['router']['id'],
                        n['network']['id'],
                        ext_ips=[{'subnet_id': s1['subnet']['id']}])
                fip1 = (res1['router']['external_gateway_info']
                        ['external_fixed_ips'][0])
                self.assertEqual(s1['subnet']['id'], fip1['subnet_id'])
                res2 = self._add_external_gateway_to_router(
                        r['router']['id'],
                        n['network']['id'],
                        ext_ips=[{'ip_address': fip1['ip_address'],
                                  'subnet_id': s1['subnet']['id']},
                                 {'subnet_id': s2['subnet']['id']}])
                self.assertEqual(fip1, res2['router']['external_gateway_info']
                                           ['external_fixed_ips'][0])
                fip2 = (res2['router']['external_gateway_info']
                        ['external_fixed_ips'][1])
                self.assertEqual(s2['subnet']['id'], fip2['subnet_id'])
                self.assertNotEqual(fip1['subnet_id'],
                                    fip2['subnet_id'])
                self.assertNotEqual(fip1['ip_address'],
                                    fip2['ip_address'])

    def test_router_update_gateway_upon_subnet_create_ipv6(self):
        with self.network() as n:
            with self.subnet(network=n) as s1, self.router() as r:
                self._set_net_external(n['network']['id'])
                res1 = self._add_external_gateway_to_router(
                          r['router']['id'],
                          n['network']['id'],
                          ext_ips=[{'subnet_id': s1['subnet']['id']}])
                fip1 = (res1['router']['external_gateway_info']
                        ['external_fixed_ips'][0])
                sres = self._create_subnet(self.fmt, net_id=n['network']['id'],
                                         ip_version=6, cidr='2001:db8::/32',
                                         expected_res_status=(
                                             exc.HTTPCreated.code))
                s2 = self.deserialize(self.fmt, sres)
                res2 = self._show('routers', r['router']['id'])
                self.assertEqual(fip1, res2['router']['external_gateway_info']
                                           ['external_fixed_ips'][0])
                fip2 = (res2['router']['external_gateway_info']
                        ['external_fixed_ips'][1])
                self.assertEqual(s2['subnet']['id'], fip2['subnet_id'])
                self.assertNotEqual(fip1['subnet_id'], fip2['subnet_id'])
                self.assertNotEqual(fip1['ip_address'], fip2['ip_address'])

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        """Create subnet should not cause excess fixed IPs on router gw

        If a router gateway port has the maximum of one IPv4 and one IPv6
        fixed, create subnet should not add any more IP addresses to the port
        (unless this is the subnet is a SLAAC/DHCPv6-stateless subnet in which
        case the addresses are added automatically)

        """
        with self.router() as r, self.network() as n:
            with self.subnet(cidr='10.0.0.0/24', network=n) as s1, (
                    self.subnet(ip_version=6, cidr='2001:db8::/64',
                        network=n)) as s2:
                self._set_net_external(n['network']['id'])
                self._add_external_gateway_to_router(
                        r['router']['id'],
                        n['network']['id'],
                        ext_ips=[{'subnet_id': s1['subnet']['id']},
                                 {'subnet_id': s2['subnet']['id']}],
                        expected_code=exc.HTTPOk.code)
                res1 = self._show('routers', r['router']['id'])
                original_fips = (res1['router']['external_gateway_info']
                                 ['external_fixed_ips'])
                # Add another IPv4 subnet - a fip SHOULD NOT be added
                # to the external gateway port as it already has a v4 address
                self._create_subnet(self.fmt, net_id=n['network']['id'],
                                    cidr='10.0.1.0/24')
                res2 = self._show('routers', r['router']['id'])
                self.assertEqual(original_fips,
                                 res2['router']['external_gateway_info']
                                 ['external_fixed_ips'])
                # Add a SLAAC subnet - a fip from this subnet SHOULD be added
                # to the external gateway port
                s3 = self.deserialize(self.fmt,
                        self._create_subnet(self.fmt,
                            net_id=n['network']['id'],
                            ip_version=6, cidr='2001:db8:1::/64',
                            ipv6_ra_mode=l3_constants.IPV6_SLAAC,
                            ipv6_address_mode=l3_constants.IPV6_SLAAC))
                res3 = self._show('routers', r['router']['id'])
                fips = (res3['router']['external_gateway_info']
                        ['external_fixed_ips'])
                fip_subnet_ids = [fip['subnet_id'] for fip in fips]
                self.assertIn(s1['subnet']['id'], fip_subnet_ids)
                self.assertIn(s2['subnet']['id'], fip_subnet_ids)
                self.assertIn(s3['subnet']['id'], fip_subnet_ids)
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    n['network']['id'])

    def _test_router_add_interface_subnet(self, router, subnet, msg=None):
        exp_notifications = ['router.create.start',
                             'router.create.end',
                             'network.create.start',
                             'network.create.end',
                             'subnet.create.start',
                             'subnet.create.end',
                             'router.interface.create',
                             'router.interface.delete']
        body = self._router_interface_action('add',
                                             router['router']['id'],
                                             subnet['subnet']['id'],
                                             None)
        self.assertIn('port_id', body, msg)

        # fetch port and confirm device_id
        r_port_id = body['port_id']
        port = self._show('ports', r_port_id)
        self.assertEqual(port['port']['device_id'],
                         router['router']['id'], msg)

        self._router_interface_action('remove',
                                      router['router']['id'],
                                      subnet['subnet']['id'],
                                      None)
        self._show('ports', r_port_id,
                   expected_code=exc.HTTPNotFound.code)

        self.assertEqual(
            set(exp_notifications),
            set(n['event_type'] for n in fake_notifier.NOTIFICATIONS), msg)

        for n in fake_notifier.NOTIFICATIONS:
            if n['event_type'].startswith('router.interface.'):
                payload = n['payload']['router_interface']
                self.assertIn('id', payload)
                self.assertEqual(payload['id'], router['router']['id'])
                self.assertIn('tenant_id', payload)
                stid = subnet['subnet']['tenant_id']
                # tolerate subnet tenant deliberately set to '' in the
                # nsx metadata access case
                self.assertIn(payload['tenant_id'], [stid, ''], msg)

    def test_router_add_interface_subnet(self):
        fake_notifier.reset()
        with self.router() as r:
            with self.network() as n:
                with self.subnet(network=n) as s:
                    self._test_router_add_interface_subnet(r, s)

    def test_router_add_interface_ipv6_subnet(self):
        """Test router-interface-add for valid ipv6 subnets.

        Verify the valid use-cases of an IPv6 subnet where we
        are allowed to associate to the Neutron Router are successful.
        """
        slaac = l3_constants.IPV6_SLAAC
        stateful = l3_constants.DHCPV6_STATEFUL
        stateless = l3_constants.DHCPV6_STATELESS
        use_cases = [{'msg': 'IPv6 Subnet Modes (slaac, none)',
                      'ra_mode': slaac, 'address_mode': None},
                     {'msg': 'IPv6 Subnet Modes (none, none)',
                      'ra_mode': None, 'address_mode': None},
                     {'msg': 'IPv6 Subnet Modes (dhcpv6-stateful, none)',
                      'ra_mode': stateful, 'address_mode': None},
                     {'msg': 'IPv6 Subnet Modes (dhcpv6-stateless, none)',
                      'ra_mode': stateless, 'address_mode': None},
                     {'msg': 'IPv6 Subnet Modes (slaac, slaac)',
                      'ra_mode': slaac, 'address_mode': slaac},
                     {'msg': 'IPv6 Subnet Modes (dhcpv6-stateful,'
                      'dhcpv6-stateful)', 'ra_mode': stateful,
                      'address_mode': stateful},
                     {'msg': 'IPv6 Subnet Modes (dhcpv6-stateless,'
                      'dhcpv6-stateless)', 'ra_mode': stateless,
                      'address_mode': stateless}]
        for uc in use_cases:
            fake_notifier.reset()
            with self.router() as r, self.network() as n:
                with self.subnet(network=n, cidr='fd00::1/64',
                                 gateway_ip='fd00::1', ip_version=6,
                                 ipv6_ra_mode=uc['ra_mode'],
                                 ipv6_address_mode=uc['address_mode']) as s:
                    self._test_router_add_interface_subnet(r, s, uc['msg'])

    def test_router_add_interface_multiple_ipv4_subnets(self):
        """Test router-interface-add for multiple ipv4 subnets.

        Verify that adding multiple ipv4 subnets from the same network
        to a router places them all on different router interfaces.
        """
        with self.router() as r, self.network() as n:
            with self.subnet(network=n, cidr='10.0.0.0/24') as s1, (
                 self.subnet(network=n, cidr='10.0.1.0/24')) as s2:
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s1['subnet']['id'],
                                                         None)
                    pid1 = body['port_id']
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s2['subnet']['id'],
                                                         None)
                    pid2 = body['port_id']
                    self.assertNotEqual(pid1, pid2)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s1['subnet']['id'], None)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s2['subnet']['id'], None)

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        """Test router-interface-add for multiple ipv6 subnets on a network.

        Verify that adding multiple ipv6 subnets from the same network
        to a router places them all on the same router interface.
        """
        with self.router() as r, self.network() as n:
            with (self.subnet(network=n, cidr='fd00::1/64', ip_version=6)
                  ) as s1, self.subnet(network=n, cidr='fd01::1/64',
                                       ip_version=6) as s2:
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s1['subnet']['id'],
                                                         None)
                    pid1 = body['port_id']
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s2['subnet']['id'],
                                                         None)
                    pid2 = body['port_id']
                    self.assertEqual(pid1, pid2)
                    port = self._show('ports', pid1)
                    self.assertEqual(2, len(port['port']['fixed_ips']))
                    port_subnet_ids = [fip['subnet_id'] for fip in
                                       port['port']['fixed_ips']]
                    self.assertIn(s1['subnet']['id'], port_subnet_ids)
                    self.assertIn(s2['subnet']['id'], port_subnet_ids)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s1['subnet']['id'], None)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s2['subnet']['id'], None)

    def test_router_add_interface_multiple_ipv6_subnets_different_net(self):
        """Test router-interface-add for ipv6 subnets on different networks.

        Verify that adding multiple ipv6 subnets from different networks
        to a router places them on different router interfaces.
        """
        with self.router() as r, self.network() as n1, self.network() as n2:
            with (self.subnet(network=n1, cidr='fd00::1/64', ip_version=6)
                  ) as s1, self.subnet(network=n2, cidr='fd01::1/64',
                                       ip_version=6) as s2:
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s1['subnet']['id'],
                                                         None)
                    pid1 = body['port_id']
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s2['subnet']['id'],
                                                         None)
                    pid2 = body['port_id']
                    self.assertNotEqual(pid1, pid2)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s1['subnet']['id'], None)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s2['subnet']['id'], None)

    def test_router_add_iface_ipv6_ext_ra_subnet_returns_400(self):
        """Test router-interface-add for in-valid ipv6 subnets.

        Verify that an appropriate error message is displayed when
        an IPv6 subnet configured to use an external_router for Router
        Advertisements (i.e., ipv6_ra_mode is None and ipv6_address_mode
        is not None) is attempted to associate with a Neutron Router.
        """
        use_cases = [{'msg': 'IPv6 Subnet Modes (none, slaac)',
                      'ra_mode': None,
                      'address_mode': l3_constants.IPV6_SLAAC},
                     {'msg': 'IPv6 Subnet Modes (none, dhcpv6-stateful)',
                      'ra_mode': None,
                      'address_mode': l3_constants.DHCPV6_STATEFUL},
                     {'msg': 'IPv6 Subnet Modes (none, dhcpv6-stateless)',
                      'ra_mode': None,
                      'address_mode': l3_constants.DHCPV6_STATELESS}]
        for uc in use_cases:
            with self.router() as r, self.network() as n:
                with self.subnet(network=n, cidr='fd00::1/64',
                                 gateway_ip='fd00::1', ip_version=6,
                                 ipv6_ra_mode=uc['ra_mode'],
                                 ipv6_address_mode=uc['address_mode']) as s:
                    exp_code = exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  None,
                                                  expected_code=exp_code,
                                                  msg=uc['msg'])

    def test_router_add_interface_ipv6_subnet_without_gateway_ip(self):
        with self.router() as r:
            with self.subnet(ip_version=6, cidr='fe80::/64',
                             gateway_ip=None) as s:
                error_code = exc.HTTPBadRequest.code
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None,
                                              expected_code=error_code)

    def test_router_add_interface_subnet_with_bad_tenant_returns_404(self):
        tenant_id = _uuid()
        with self.router(tenant_id=tenant_id, set_context=True) as r:
            with self.network(tenant_id=tenant_id, set_context=True) as n:
                with self.subnet(network=n, set_context=True) as s:
                    err_code = exc.HTTPNotFound.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  None,
                                                  expected_code=err_code,
                                                  tenant_id='bad_tenant')
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s['subnet']['id'],
                                                         None)
                    self.assertIn('port_id', body)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  None,
                                                  expected_code=err_code,
                                                  tenant_id='bad_tenant')

    def test_router_add_interface_subnet_with_port_from_other_tenant(self):
        tenant_id = _uuid()
        other_tenant_id = _uuid()
        with self.router(tenant_id=tenant_id) as r,\
                self.network(tenant_id=tenant_id) as n1,\
                self.network(tenant_id=other_tenant_id) as n2:
            with self.subnet(network=n1, cidr='10.0.0.0/24') as s1,\
                    self.subnet(network=n2, cidr='10.1.0.0/24') as s2:
                body = self._router_interface_action(
                    'add',
                    r['router']['id'],
                    s2['subnet']['id'],
                    None)
                self.assertIn('port_id', body)
                self._router_interface_action(
                    'add',
                    r['router']['id'],
                    s1['subnet']['id'],
                    None,
                    tenant_id=tenant_id)
                self.assertIn('port_id', body)

    def test_router_add_interface_port(self):
        with self.router() as r:
            with self.port() as p:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     None,
                                                     p['port']['id'])
                self.assertIn('port_id', body)
                self.assertEqual(body['port_id'], p['port']['id'])

                # fetch port and confirm device_id
                body = self._show('ports', p['port']['id'])
                self.assertEqual(body['port']['device_id'], r['router']['id'])

                # clean-up
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              None,
                                              p['port']['id'])

    def test_router_add_interface_multiple_ipv4_subnet_port_returns_400(self):
        """Test adding router port with multiple IPv4 subnets fails.

        Multiple IPv4 subnets are not allowed on a single router port.
        Ensure that adding a port with multiple IPv4 subnets to a router fails.
        """
        with self.network() as n, self.router() as r:
            with self.subnet(network=n, cidr='10.0.0.0/24') as s1, (
                 self.subnet(network=n, cidr='10.0.1.0/24')) as s2:
                fixed_ips = [{'subnet_id': s1['subnet']['id']},
                             {'subnet_id': s2['subnet']['id']}]
                with self.port(subnet=s1, fixed_ips=fixed_ips) as p:
                    exp_code = exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'],
                                                  expected_code=exp_code)

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        """Ensure unique IPv6 router ports per network id.

        Adding a router port containing one or more IPv6 subnets with the same
        network id as an existing router port should fail. This is so
        there is no ambiguity regarding on which port to add an IPv6 subnet
        when executing router-interface-add with a subnet and no port.
        """
        with self.network() as n, self.router() as r:
            with self.subnet(network=n, cidr='fd00::/64',
                             ip_version=6) as s1, (
                 self.subnet(network=n, cidr='fd01::/64',
                             ip_version=6)) as s2:
                with self.port(subnet=s1) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    exp_code = exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'],
                                                  expected_code=exp_code)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)

    def test_router_add_interface_multiple_ipv6_subnet_port(self):
        """A port with multiple IPv6 subnets can be added to a router

        Create a port with multiple associated IPv6 subnets and attach
        it to a router. The action should succeed.
        """
        with self.network() as n, self.router() as r:
            with self.subnet(network=n, cidr='fd00::/64',
                             ip_version=6) as s1, (
                 self.subnet(network=n, cidr='fd01::/64',
                             ip_version=6)) as s2:
                fixed_ips = [{'subnet_id': s1['subnet']['id']},
                             {'subnet_id': s2['subnet']['id']}]
                with self.port(subnet=s1, fixed_ips=fixed_ips) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_add_interface_empty_port_and_subnet_ids(self):
        with self.router() as r:
            self._router_interface_action('add', r['router']['id'],
                                          None, None,
                                          expected_code=exc.
                                          HTTPBadRequest.code)

    def test_router_add_interface_port_bad_tenant_returns_404(self):
        tenant_id = _uuid()
        with self.router(tenant_id=tenant_id, set_context=True) as r:
            with self.network(tenant_id=tenant_id, set_context=True) as n:
                with self.subnet(tenant_id=tenant_id, network=n,
                                 set_context=True) as s:
                    with self.port(tenant_id=tenant_id, subnet=s,
                                   set_context=True) as p:
                        err_code = exc.HTTPNotFound.code
                        self._router_interface_action('add',
                                                    r['router']['id'],
                                                    None,
                                                    p['port']['id'],
                                                    expected_code=err_code,
                                                    tenant_id='bad_tenant')
                        self._router_interface_action('add',
                                                    r['router']['id'],
                                                    None,
                                                    p['port']['id'],
                                                    tenant_id=tenant_id)

                        # clean-up should fail as well
                        self._router_interface_action('remove',
                                                    r['router']['id'],
                                                    None,
                                                    p['port']['id'],
                                                    expected_code=err_code,
                                                    tenant_id='bad_tenant')

    def test_router_add_interface_port_without_ips(self):
        with self.network() as network, self.router() as r:
            # Create a router port without ips
            p = self._make_port(self.fmt, network['network']['id'],
                device_owner=l3_constants.DEVICE_OWNER_ROUTER_INTF)
            err_code = exc.HTTPBadRequest.code
            self._router_interface_action('add',
                                          r['router']['id'],
                                          None,
                                          p['port']['id'],
                                          expected_code=err_code)

    def test_router_add_interface_dup_subnet1_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None,
                                              expected_code=exc.
                                              HTTPBadRequest.code)

    def test_router_add_interface_dup_subnet2_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s) as p1:
                    with self.port(subnet=s) as p2:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p1['port']['id'])
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p2['port']['id'],
                                                      expected_code=exc.
                                                      HTTPBadRequest.code)

    def test_router_add_interface_overlapped_cidr_returns_400(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s1:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s1['subnet']['id'],
                                              None)

                def try_overlapped_cidr(cidr):
                    with self.subnet(cidr=cidr) as s2:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s2['subnet']['id'],
                                                      None,
                                                      expected_code=exc.
                                                      HTTPBadRequest.code)
                # another subnet with same cidr
                try_overlapped_cidr('10.0.1.0/24')
                # another subnet with overlapped cidr including s1
                try_overlapped_cidr('10.0.0.0/16')

    def test_router_add_interface_no_data_returns_400(self):
        with self.router() as r:
            self._router_interface_action('add',
                                          r['router']['id'],
                                          None,
                                          None,
                                          expected_code=exc.
                                          HTTPBadRequest.code)

    def test_router_add_interface_with_both_ids_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  p['port']['id'],
                                                  expected_code=exc.
                                                  HTTPBadRequest.code)

    def test_router_add_gateway_dup_subnet1_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'],
                    expected_code=exc.HTTPBadRequest.code)

    def test_router_add_gateway_dup_subnet2_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None,
                                              expected_code=exc.
                                              HTTPBadRequest.code)

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        """Ensure external gateway set doesn't add excess IPs on router gw

        Setting the gateway of a router to an external network with more than
        one IPv4 and one IPv6 subnet should only add an address from the first
        IPv4 subnet, an address from the first IPv6-stateful subnet, and an
        address from each IPv6-stateless (SLAAC and DHCPv6-stateless) subnet

        """
        with self.router() as r, self.network() as n:
            with self.subnet(
                    cidr='10.0.0.0/24', network=n) as s1, (
                 self.subnet(
                    cidr='10.0.1.0/24', network=n)) as s2, (
                 self.subnet(
                    cidr='2001:db8::/64', network=n,
                    ip_version=6,
                    ipv6_ra_mode=l3_constants.IPV6_SLAAC,
                    ipv6_address_mode=l3_constants.IPV6_SLAAC)) as s3, (
                 self.subnet(
                    cidr='2001:db8:1::/64', network=n,
                    ip_version=6,
                    ipv6_ra_mode=l3_constants.DHCPV6_STATEFUL,
                    ipv6_address_mode=l3_constants.DHCPV6_STATEFUL)) as s4, (
                 self.subnet(
                    cidr='2001:db8:2::/64', network=n,
                    ip_version=6,
                    ipv6_ra_mode=l3_constants.DHCPV6_STATELESS,
                    ipv6_address_mode=l3_constants.DHCPV6_STATELESS)) as s5:
                self._set_net_external(n['network']['id'])
                self._add_external_gateway_to_router(
                        r['router']['id'],
                        n['network']['id'])
                res = self._show('routers', r['router']['id'])
                fips = (res['router']['external_gateway_info']
                        ['external_fixed_ips'])
                fip_subnet_ids = {fip['subnet_id'] for fip in fips}
                # one of s1 or s2 should be in the list.
                if s1['subnet']['id'] in fip_subnet_ids:
                    self.assertEqual({s1['subnet']['id'],
                                      s3['subnet']['id'],
                                      s4['subnet']['id'],
                                      s5['subnet']['id']},
                                     fip_subnet_ids)
                else:
                    self.assertEqual({s2['subnet']['id'],
                                      s3['subnet']['id'],
                                      s4['subnet']['id'],
                                      s5['subnet']['id']},
                                     fip_subnet_ids)
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    n['network']['id'])

    def test_router_add_and_remove_gateway(self):
        with self.router() as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                net_id = body['router']['external_gateway_info']['network_id']
                self.assertEqual(net_id, s['subnet']['network_id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertIsNone(gw_info)

    def test_router_add_and_remove_gateway_tenant_ctx(self):
        with self.router(tenant_id='noadmin',
                         set_context=True) as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                ctx = context.Context('', 'noadmin')
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'],
                    neutron_context=ctx)
                body = self._show('routers', r['router']['id'])
                net_id = body['router']['external_gateway_info']['network_id']
                self.assertEqual(net_id, s['subnet']['network_id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertIsNone(gw_info)

    def test_create_router_port_with_device_id_of_other_teants_router(self):
        with self.router() as admin_router:
            with self.network(tenant_id='tenant_a',
                              set_context=True) as n:
                with self.subnet(network=n):
                    for device_owner in l3_constants.ROUTER_INTERFACE_OWNERS:
                        self._create_port(
                            self.fmt, n['network']['id'],
                            tenant_id='tenant_a',
                            device_id=admin_router['router']['id'],
                            device_owner=device_owner,
                            set_context=True,
                            expected_res_status=exc.HTTPConflict.code)

    def test_create_non_router_port_device_id_of_other_teants_router_update(
        self):
        # This tests that HTTPConflict is raised if we create a non-router
        # port that matches the device_id of another tenants router and then
        # we change the device_owner to be network:router_interface.
        with self.router() as admin_router:
            with self.network(tenant_id='tenant_a',
                              set_context=True) as n:
                with self.subnet(network=n):
                    for device_owner in l3_constants.ROUTER_INTERFACE_OWNERS:
                        port_res = self._create_port(
                            self.fmt, n['network']['id'],
                            tenant_id='tenant_a',
                            device_id=admin_router['router']['id'],
                            set_context=True)
                        port = self.deserialize(self.fmt, port_res)
                        neutron_context = context.Context('', 'tenant_a')
                        data = {'port': {'device_owner': device_owner}}
                        self._update('ports', port['port']['id'], data,
                                     neutron_context=neutron_context,
                                     expected_code=exc.HTTPConflict.code)

    def test_update_port_device_id_to_different_tenants_router(self):
        with self.router() as admin_router:
            with self.router(tenant_id='tenant_a',
                             set_context=True) as tenant_router:
                with self.network(tenant_id='tenant_a',
                                  set_context=True) as n:
                    with self.subnet(network=n) as s:
                        port = self._router_interface_action(
                            'add', tenant_router['router']['id'],
                            s['subnet']['id'], None, tenant_id='tenant_a')
                        neutron_context = context.Context('', 'tenant_a')
                        data = {'port':
                                {'device_id': admin_router['router']['id']}}
                        self._update('ports', port['port_id'], data,
                                     neutron_context=neutron_context,
                                     expected_code=exc.HTTPConflict.code)

    def test_router_add_gateway_invalid_network_returns_400(self):
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                "foobar", expected_code=exc.HTTPBadRequest.code)

    def test_router_add_gateway_non_existent_network_returns_404(self):
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                _uuid(), expected_code=exc.HTTPNotFound.code)

    def test_router_add_gateway_net_not_external_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                # intentionally do not set net as external
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'],
                    expected_code=exc.HTTPBadRequest.code)

    def test_router_add_gateway_no_subnet(self):
        with self.router() as r:
            with self.network() as n:
                self._set_net_external(n['network']['id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    n['network']['id'])
                body = self._show('routers', r['router']['id'])
                net_id = body['router']['external_gateway_info']['network_id']
                self.assertEqual(net_id, n['network']['id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    n['network']['id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertIsNone(gw_info)

    def test_router_remove_interface_inuse_returns_409(self):
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
                self._delete('routers', r['router']['id'],
                             expected_code=exc.HTTPConflict.code)

    def test_router_remove_interface_callback_failure_returns_409(self):
        with self.router() as r,\
                self.subnet() as s,\
                mock.patch.object(registry, 'notify') as notify:
            errors = [
                exceptions.NotificationError(
                    'foo_callback_id', n_exc.InUse()),
            ]
            # we fail the first time, but not the second, when
            # the clean-up takes place
            notify.side_effect = [
                exceptions.CallbackFailure(errors=errors), None
            ]
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s['subnet']['id'],
                                          None)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s['subnet']['id'],
                None,
                exc.HTTPConflict.code)

    def test_router_clear_gateway_callback_failure_returns_409(self):
        with self.router() as r,\
                self.subnet() as s,\
                mock.patch.object(registry, 'notify') as notify:
            errors = [
                exceptions.NotificationError(
                    'foo_callback_id', n_exc.InUse()),
            ]
            notify.side_effect = exceptions.CallbackFailure(errors=errors)
            self._set_net_external(s['subnet']['network_id'])
            self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
            self._remove_external_gateway_from_router(
                r['router']['id'],
                s['subnet']['network_id'],
                external_gw_info={},
                expected_code=exc.HTTPConflict.code)

    def test_router_remove_interface_wrong_subnet_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port() as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  p['port']['id'],
                                                  exc.HTTPBadRequest.code)

    def test_router_remove_interface_nothing_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  None,
                                                  exc.HTTPBadRequest.code)
                    #remove properly to clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_remove_interface_returns_200(self):
        with self.router() as r:
            with self.port() as p:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     None,
                                                     p['port']['id'])
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              None,
                                              p['port']['id'],
                                              expected_body=body)

    def test_router_remove_interface_with_both_ids_returns_200(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  p['port']['id'])

    def test_router_remove_interface_wrong_port_returns_404(self):
        with self.router() as r:
            with self.subnet():
                with self.port() as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # create another port for testing failure case
                    res = self._create_port(self.fmt, p['port']['network_id'])
                    p2 = self.deserialize(self.fmt, res)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p2['port']['id'],
                                                  exc.HTTPNotFound.code)

    def test_router_remove_ipv6_subnet_from_interface(self):
        """Delete a subnet from a router interface

        Verify that deleting a subnet with router-interface-delete removes
        that subnet when there are multiple subnets on the interface and
        removes the interface when it is the last subnet on the interface.
        """
        with self.router() as r, self.network() as n:
            with (self.subnet(network=n, cidr='fd00::1/64', ip_version=6)
                  ) as s1, self.subnet(network=n, cidr='fd01::1/64',
                                       ip_version=6) as s2:
                body = self._router_interface_action('add', r['router']['id'],
                                                     s1['subnet']['id'],
                                                     None)
                self._router_interface_action('add', r['router']['id'],
                                              s2['subnet']['id'], None)
                port = self._show('ports', body['port_id'])
                self.assertEqual(2, len(port['port']['fixed_ips']))
                self._router_interface_action('remove', r['router']['id'],
                                              s1['subnet']['id'], None)
                port = self._show('ports', body['port_id'])
                self.assertEqual(1, len(port['port']['fixed_ips']))
                self._router_interface_action('remove', r['router']['id'],
                                              s2['subnet']['id'], None)
                exp_code = exc.HTTPNotFound.code
                port = self._show('ports', body['port_id'],
                                  expected_code=exp_code)

    def test_router_delete(self):
        with self.router() as router:
            router_id = router['router']['id']
        req = self.new_show_request('router', router_id)
        res = req.get_response(self._api_for_resource('router'))
        self.assertEqual(res.status_int, 404)

    def test_router_delete_with_port_existed_returns_409(self):
        with self.subnet() as subnet:
            res = self._create_router(self.fmt, _uuid())
            router = self.deserialize(self.fmt, res)
            self._router_interface_action('add',
                                          router['router']['id'],
                                          subnet['subnet']['id'],
                                          None)
            self._delete('routers', router['router']['id'],
                         exc.HTTPConflict.code)

    def test_router_delete_with_floatingip_existed_returns_409(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.subnet(cidr='12.0.0.0/24') as public_sub:
                self._set_net_external(public_sub['subnet']['network_id'])
                res = self._create_router(self.fmt, _uuid())
                r = self.deserialize(self.fmt, res)
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])
                self._router_interface_action('add', r['router']['id'],
                                              private_sub['subnet']['id'],
                                              None)
                res = self._create_floatingip(
                    self.fmt, public_sub['subnet']['network_id'],
                    port_id=p['port']['id'])
                self.assertEqual(res.status_int, exc.HTTPCreated.code)
                self._delete('routers', r['router']['id'],
                             expected_code=exc.HTTPConflict.code)

    def test_router_show(self):
        name = 'router1'
        tenant_id = _uuid()
        expected_value = [('name', name), ('tenant_id', tenant_id),
                          ('admin_state_up', True), ('status', 'ACTIVE'),
                          ('external_gateway_info', None)]
        with self.router(name='router1', admin_state_up=True,
                         tenant_id=tenant_id) as router:
            res = self._show('routers', router['router']['id'])
            for k, v in expected_value:
                self.assertEqual(res['router'][k], v)

    def test_network_update_external_failure(self):
        with self.router() as r:
            with self.subnet() as s1:
                self._set_net_external(s1['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s1['subnet']['network_id'])
                self._update('networks', s1['subnet']['network_id'],
                             {'network': {external_net.EXTERNAL: False}},
                             expected_code=exc.HTTPConflict.code)

    def test_network_update_external(self):
        with self.router() as r:
            with self.network('test_net') as testnet:
                self._set_net_external(testnet['network']['id'])
                with self.subnet() as s1:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])
                    self._update('networks', testnet['network']['id'],
                                 {'network': {external_net.EXTERNAL: False}})

    def test_floatingip_crd_ops(self):
        with self.floatingip_with_assoc() as fip:
            self._validate_floating_ip(fip)

        # post-delete, check that it is really gone
        body = self._list('floatingips')
        self.assertEqual(len(body['floatingips']), 0)

        self._show('floatingips', fip['floatingip']['id'],
                   expected_code=exc.HTTPNotFound.code)

    def _test_floatingip_with_assoc_fails(self, plugin_method):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)
                    with mock.patch(plugin_method) as pl:
                        pl.side_effect = n_exc.BadRequest(
                            resource='floatingip',
                            msg='fake_error')
                        res = self._create_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'],
                            port_id=private_port['port']['id'])
                        self.assertEqual(res.status_int, 400)
                    for p in self._list('ports')['ports']:
                        if (p['device_owner'] ==
                            l3_constants.DEVICE_OWNER_FLOATINGIP):
                            self.fail('garbage port is not deleted')

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            'neutron.db.l3_db.L3_NAT_db_mixin._check_and_get_fip_assoc')

    def test_create_floatingip_with_assoc(
        self, expected_status=l3_constants.FLOATINGIP_STATUS_ACTIVE):
        with self.floatingip_with_assoc() as fip:
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertEqual(body['floatingip']['id'],
                             fip['floatingip']['id'])
            self.assertEqual(body['floatingip']['port_id'],
                             fip['floatingip']['port_id'])
            self.assertEqual(expected_status, body['floatingip']['status'])
            self.assertIsNotNone(body['floatingip']['fixed_ip_address'])
            self.assertIsNotNone(body['floatingip']['router_id'])

    def test_floating_port_status_not_applicable(self):
        with self.floatingip_with_assoc():
            port_body = self._list('ports',
               query_params='device_owner=network:floatingip')['ports'][0]
            self.assertEqual(l3_constants.PORT_STATUS_NOTAPPLICABLE,
                             port_body['status'])

    def test_floatingip_update(
        self, expected_status=l3_constants.FLOATINGIP_STATUS_ACTIVE):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['fixed_ip_address'])
                self.assertEqual(body['floatingip']['status'], expected_status)

                port_id = p['port']['id']
                ip_address = p['port']['fixed_ips'][0]['ip_address']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEqual(body['floatingip']['port_id'], port_id)
                self.assertEqual(body['floatingip']['fixed_ip_address'],
                                 ip_address)

    def test_floatingip_create_different_fixed_ip_same_port(self):
        '''This tests that it is possible to delete a port that has
        multiple floating ip addresses associated with it (each floating
        address associated with a unique fixed address).
        '''

        with self.router() as r:
            with self.subnet(cidr='11.0.0.0/24') as public_sub:
                self._set_net_external(public_sub['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])

                with self.subnet() as private_sub:
                    ip_range = list(netaddr.IPNetwork(
                        private_sub['subnet']['cidr']))
                    fixed_ips = [{'ip_address': str(ip_range[-3])},
                                 {'ip_address': str(ip_range[-2])}]

                    self._router_interface_action(
                        'add', r['router']['id'],
                        private_sub['subnet']['id'], None)

                    with self.port(subnet=private_sub,
                                   fixed_ips=fixed_ips) as p:

                        fip1 = self._make_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'],
                            p['port']['id'],
                            fixed_ip=str(ip_range[-2]))
                        fip2 = self._make_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'],
                            p['port']['id'],
                            fixed_ip=str(ip_range[-3]))

                        # Test that floating ips are assigned successfully.
                        body = self._show('floatingips',
                                          fip1['floatingip']['id'])
                        self.assertEqual(
                            body['floatingip']['port_id'],
                            fip1['floatingip']['port_id'])

                        body = self._show('floatingips',
                                          fip2['floatingip']['id'])
                        self.assertEqual(
                            body['floatingip']['port_id'],
                            fip2['floatingip']['port_id'])
                    self._delete('ports', p['port']['id'])
                    # Test that port has been successfully deleted.
                    body = self._show('ports', p['port']['id'],
                                      expected_code=exc.HTTPNotFound.code)

    def test_floatingip_update_different_fixed_ip_same_port(self):
        with self.subnet() as s:
            ip_range = list(netaddr.IPNetwork(s['subnet']['cidr']))
            fixed_ips = [{'ip_address': str(ip_range[-3])},
                         {'ip_address': str(ip_range[-2])}]
            with self.port(subnet=s, fixed_ips=fixed_ips) as p:
                with self.floatingip_with_assoc(
                    port_id=p['port']['id'],
                    fixed_ip=str(ip_range[-3])) as fip:
                    body = self._show('floatingips', fip['floatingip']['id'])
                    self.assertEqual(fip['floatingip']['id'],
                                     body['floatingip']['id'])
                    self.assertEqual(fip['floatingip']['port_id'],
                                     body['floatingip']['port_id'])
                    self.assertEqual(str(ip_range[-3]),
                                     body['floatingip']['fixed_ip_address'])
                    self.assertIsNotNone(body['floatingip']['router_id'])
                    body_2 = self._update(
                        'floatingips', fip['floatingip']['id'],
                        {'floatingip': {'port_id': p['port']['id'],
                                        'fixed_ip_address': str(ip_range[-2])}
                         })
                    self.assertEqual(fip['floatingip']['port_id'],
                                     body_2['floatingip']['port_id'])
                    self.assertEqual(str(ip_range[-2]),
                                     body_2['floatingip']['fixed_ip_address'])

    def test_floatingip_update_different_router(self):
        # Create subnet with different CIDRs to account for plugins which
        # do not support overlapping IPs
        with self.subnet(cidr='10.0.0.0/24') as s1,\
                self.subnet(cidr='10.0.1.0/24') as s2:
            with self.port(subnet=s1) as p1, self.port(subnet=s2) as p2:
                private_sub1 = {'subnet':
                                {'id':
                                 p1['port']['fixed_ips'][0]['subnet_id']}}
                private_sub2 = {'subnet':
                                {'id':
                                 p2['port']['fixed_ips'][0]['subnet_id']}}
                with self.subnet(cidr='12.0.0.0/24') as public_sub:
                    with self.floatingip_no_assoc_with_public_sub(
                        private_sub1,
                        public_sub=public_sub) as (fip1, r1),\
                            self.floatingip_no_assoc_with_public_sub(
                                private_sub2,
                                public_sub=public_sub) as (fip2, r2):

                        def assert_no_assoc(fip):
                            body = self._show('floatingips',
                                              fip['floatingip']['id'])
                            self.assertIsNone(body['floatingip']['port_id'])
                            self.assertIsNone(
                                body['floatingip']['fixed_ip_address'])

                        assert_no_assoc(fip1)
                        assert_no_assoc(fip2)

                        def associate_and_assert(fip, port):
                            port_id = port['port']['id']
                            ip_address = (port['port']['fixed_ips']
                                          [0]['ip_address'])
                            body = self._update(
                                'floatingips', fip['floatingip']['id'],
                                {'floatingip': {'port_id': port_id}})
                            self.assertEqual(body['floatingip']['port_id'],
                                             port_id)
                            self.assertEqual(
                                body['floatingip']['fixed_ip_address'],
                                ip_address)
                            return body['floatingip']['router_id']

                        fip1_r1_res = associate_and_assert(fip1, p1)
                        self.assertEqual(fip1_r1_res, r1['router']['id'])
                        # The following operation will associate the floating
                        # ip to a different router
                        fip1_r2_res = associate_and_assert(fip1, p2)
                        self.assertEqual(fip1_r2_res, r2['router']['id'])
                        fip2_r1_res = associate_and_assert(fip2, p1)
                        self.assertEqual(fip2_r1_res, r1['router']['id'])
                        # disassociate fip1
                        self._update(
                            'floatingips', fip1['floatingip']['id'],
                            {'floatingip': {'port_id': None}})
                        fip2_r2_res = associate_and_assert(fip2, p2)
                        self.assertEqual(fip2_r2_res, r2['router']['id'])

    def test_floatingip_port_delete(self):
        with self.subnet() as private_sub:
            with self.floatingip_no_assoc(private_sub) as fip:
                with self.port(subnet=private_sub) as p:
                    body = self._update('floatingips', fip['floatingip']['id'],
                                        {'floatingip':
                                         {'port_id': p['port']['id']}})
                # note: once this port goes out of scope, the port will be
                # deleted, which is what we want to test. We want to confirm
                # that the fields are set back to None
                self._delete('ports', p['port']['id'])
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertEqual(body['floatingip']['id'],
                                 fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['fixed_ip_address'])
                self.assertIsNone(body['floatingip']['router_id'])

    def test_two_fips_one_port_invalid_return_409(self):
        with self.floatingip_with_assoc() as fip1:
            res = self._create_floatingip(
                self.fmt,
                fip1['floatingip']['floating_network_id'],
                fip1['floatingip']['port_id'])
            self.assertEqual(res.status_int, exc.HTTPConflict.code)

    def test_floating_ip_direct_port_delete_returns_409(self):
        found = False
        with self.floatingip_with_assoc():
            for p in self._list('ports')['ports']:
                if p['device_owner'] == l3_constants.DEVICE_OWNER_FLOATINGIP:
                    self._delete('ports', p['id'],
                                 expected_code=exc.HTTPConflict.code)
                    found = True
        self.assertTrue(found)

    def _test_floatingip_with_invalid_create_port(self, plugin_class):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.subnet(cidr='12.0.0.0/24') as public_sub:
                self._set_net_external(public_sub['subnet']['network_id'])
                res = self._create_router(self.fmt, _uuid())
                r = self.deserialize(self.fmt, res)
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])
                self._router_interface_action(
                    'add', r['router']['id'],
                    private_sub['subnet']['id'],
                    None)

                with mock.patch(plugin_class + '.create_port') as createport:
                    createport.return_value = {'fixed_ips': []}
                    res = self._create_floatingip(
                        self.fmt, public_sub['subnet']['network_id'],
                        port_id=p['port']['id'])
                    self.assertEqual(res.status_int,
                                     exc.HTTPBadRequest.code)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(
            'neutron.db.db_base_plugin_v2.NeutronDbPluginV2')

    def test_create_floatingip_no_ext_gateway_return_404(self):
        with self.subnet() as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router():
                    res = self._create_floatingip(
                        self.fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    # this should be some kind of error
                    self.assertEqual(res.status_int, exc.HTTPNotFound.code)

    def test_create_floating_non_ext_network_returns_400(self):
        with self.subnet() as public_sub:
            # normally we would set the network of public_sub to be
            # external, but the point of this test is to handle when
            # that is not the case
            with self.router():
                res = self._create_floatingip(
                    self.fmt,
                    public_sub['subnet']['network_id'])
                self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_floatingip_no_public_subnet_returns_400(self):
        with self.network() as public_network:
            with self.port() as private_port:
                with self.router() as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    self._router_interface_action('add', r['router']['id'],
                                                  private_sub['subnet']['id'],
                                                  None)

                    res = self._create_floatingip(
                        self.fmt,
                        public_network['network']['id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_floatingip_invalid_floating_network_id_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip(self.fmt, 'iamnotanuuid',
                                      uuidutils.generate_uuid(), '192.168.0.1')
        self.assertEqual(res.status_int, 400)

    def test_create_floatingip_invalid_floating_port_id_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip(self.fmt, uuidutils.generate_uuid(),
                                      'iamnotanuuid', '192.168.0.1')
        self.assertEqual(res.status_int, 400)

    def test_create_floatingip_invalid_fixed_ip_address_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip(self.fmt, uuidutils.generate_uuid(),
                                      uuidutils.generate_uuid(), 'iamnotnanip')
        self.assertEqual(res.status_int, 400)

    def test_floatingip_list_with_sort(self):
        with self.subnet(cidr="10.0.0.0/24") as s1,\
                self.subnet(cidr="11.0.0.0/24") as s2,\
                self.subnet(cidr="12.0.0.0/24") as s3:
            network_id1 = s1['subnet']['network_id']
            network_id2 = s2['subnet']['network_id']
            network_id3 = s3['subnet']['network_id']
            self._set_net_external(network_id1)
            self._set_net_external(network_id2)
            self._set_net_external(network_id3)
            fp1 = self._make_floatingip(self.fmt, network_id1)
            fp2 = self._make_floatingip(self.fmt, network_id2)
            fp3 = self._make_floatingip(self.fmt, network_id3)
            self._test_list_with_sort('floatingip', (fp3, fp2, fp1),
                                      [('floating_ip_address', 'desc')])

    def test_floatingip_list_with_port_id(self):
        with self.floatingip_with_assoc() as fip:
            port_id = fip['floatingip']['port_id']
            res = self._list('floatingips',
                             query_params="port_id=%s" % port_id)
            self.assertEqual(len(res['floatingips']), 1)
            res = self._list('floatingips', query_params="port_id=aaa")
            self.assertEqual(len(res['floatingips']), 0)

    def test_floatingip_list_with_pagination(self):
        with self.subnet(cidr="10.0.0.0/24") as s1,\
                self.subnet(cidr="11.0.0.0/24") as s2,\
                self.subnet(cidr="12.0.0.0/24") as s3:
            network_id1 = s1['subnet']['network_id']
            network_id2 = s2['subnet']['network_id']
            network_id3 = s3['subnet']['network_id']
            self._set_net_external(network_id1)
            self._set_net_external(network_id2)
            self._set_net_external(network_id3)
            fp1 = self._make_floatingip(self.fmt, network_id1)
            fp2 = self._make_floatingip(self.fmt, network_id2)
            fp3 = self._make_floatingip(self.fmt, network_id3)
            self._test_list_with_pagination(
                'floatingip', (fp1, fp2, fp3),
                ('floating_ip_address', 'asc'), 2, 2)

    def test_floatingip_list_with_pagination_reverse(self):
        with self.subnet(cidr="10.0.0.0/24") as s1,\
                self.subnet(cidr="11.0.0.0/24") as s2,\
                self.subnet(cidr="12.0.0.0/24") as s3:
            network_id1 = s1['subnet']['network_id']
            network_id2 = s2['subnet']['network_id']
            network_id3 = s3['subnet']['network_id']
            self._set_net_external(network_id1)
            self._set_net_external(network_id2)
            self._set_net_external(network_id3)
            fp1 = self._make_floatingip(self.fmt, network_id1)
            fp2 = self._make_floatingip(self.fmt, network_id2)
            fp3 = self._make_floatingip(self.fmt, network_id3)
            self._test_list_with_pagination_reverse(
                'floatingip', (fp1, fp2, fp3),
                ('floating_ip_address', 'asc'), 2, 2)

    def test_floatingip_multi_external_one_internal(self):
        with self.subnet(cidr="10.0.0.0/24") as exs1,\
                self.subnet(cidr="11.0.0.0/24") as exs2,\
                self.subnet(cidr="12.0.0.0/24") as ins1:
            network_ex_id1 = exs1['subnet']['network_id']
            network_ex_id2 = exs2['subnet']['network_id']
            self._set_net_external(network_ex_id1)
            self._set_net_external(network_ex_id2)

            r2i_fixed_ips = [{'ip_address': '12.0.0.2'}]
            with self.router() as r1,\
                    self.router() as r2,\
                    self.port(subnet=ins1,
                              fixed_ips=r2i_fixed_ips) as r2i_port:
                self._add_external_gateway_to_router(
                    r1['router']['id'],
                    network_ex_id1)
                self._router_interface_action('add', r1['router']['id'],
                                              ins1['subnet']['id'],
                                              None)
                self._add_external_gateway_to_router(
                    r2['router']['id'],
                    network_ex_id2)
                self._router_interface_action('add', r2['router']['id'],
                                              None,
                                              r2i_port['port']['id'])

                with self.port(subnet=ins1,
                               fixed_ips=[{'ip_address': '12.0.0.3'}]
                               ) as private_port:

                    fp1 = self._make_floatingip(self.fmt, network_ex_id1,
                                            private_port['port']['id'],
                                            floating_ip='10.0.0.3')
                    fp2 = self._make_floatingip(self.fmt, network_ex_id2,
                                            private_port['port']['id'],
                                            floating_ip='11.0.0.3')
                    self.assertEqual(fp1['floatingip']['router_id'],
                                     r1['router']['id'])
                    self.assertEqual(fp2['floatingip']['router_id'],
                                     r2['router']['id'])

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        found = False
        with self.floatingip_with_assoc():
            for p in self._list('ports')['ports']:
                if p['device_owner'] == l3_constants.DEVICE_OWNER_ROUTER_INTF:
                    subnet_id = p['fixed_ips'][0]['subnet_id']
                    router_id = p['device_id']
                    self._router_interface_action(
                        'remove', router_id, subnet_id, None,
                        expected_code=exc.HTTPConflict.code)
                    found = True
                    break
        self.assertTrue(found)

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        found = False
        with self.floatingip_with_assoc():
            for p in self._list('ports')['ports']:
                if p['device_owner'] == l3_constants.DEVICE_OWNER_ROUTER_INTF:
                    router_id = p['device_id']
                    self._router_interface_action(
                        'remove', router_id, None, p['id'],
                        expected_code=exc.HTTPConflict.code)
                    found = True
                    break
        self.assertTrue(found)

    def _test_router_delete_subnet_inuse_returns_409(self, router, subnet):
        r, s = router, subnet
        self._router_interface_action('add',
                                      r['router']['id'],
                                      s['subnet']['id'],
                                      None)
        # subnet cannot be deleted as it's attached to a router
        self._delete('subnets', s['subnet']['id'],
                     expected_code=exc.HTTPConflict.code)

    def _ipv6_subnet(self, mode):
        return self.subnet(cidr='fd00::1/64', gateway_ip='fd00::1',
                           ip_version=6,
                           ipv6_ra_mode=mode,
                           ipv6_address_mode=mode)

    def test_router_delete_subnet_inuse_returns_409(self):
        with self.router() as r:
            with self.subnet() as s:
                self._test_router_delete_subnet_inuse_returns_409(r, s)

    def test_router_delete_ipv6_slaac_subnet_inuse_returns_409(self):
        with self.router() as r:
            with self._ipv6_subnet(l3_constants.IPV6_SLAAC) as s:
                self._test_router_delete_subnet_inuse_returns_409(r, s)

    def test_router_delete_dhcpv6_stateless_subnet_inuse_returns_409(self):
        with self.router() as r:
            with self._ipv6_subnet(l3_constants.DHCPV6_STATELESS) as s:
                self._test_router_delete_subnet_inuse_returns_409(r, s)

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        with self.network() as net:
            net_id = net['network']['id']
            self._set_net_external(net_id)
            with self.subnet(network=net):
                self._make_floatingip(self.fmt, net_id)

    def test_create_floatingip_with_specific_ip(self):
        with self.subnet(cidr='10.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fp = self._make_floatingip(self.fmt, network_id,
                                       floating_ip='10.0.0.10')
            self.assertEqual(fp['floatingip']['floating_ip_address'],
                             '10.0.0.10')

    def test_create_floatingip_with_specific_ip_out_of_allocation(self):
        with self.subnet(cidr='10.0.0.0/24',
                         allocation_pools=[
                             {'start': '10.0.0.10', 'end': '10.0.0.20'}]
                         ) as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fp = self._make_floatingip(self.fmt, network_id,
                                       floating_ip='10.0.0.30')
            self.assertEqual(fp['floatingip']['floating_ip_address'],
                             '10.0.0.30')

    def test_create_floatingip_with_specific_ip_non_admin(self):
        ctx = context.Context('user_id', 'tenant_id')

        with self.subnet(cidr='10.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            self._make_floatingip(self.fmt, network_id,
                                  set_context=ctx,
                                  floating_ip='10.0.0.10',
                                  http_status=exc.HTTPForbidden.code)

    def test_create_floatingip_with_specific_ip_out_of_subnet(self):

        with self.subnet(cidr='10.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            self._make_floatingip(self.fmt, network_id,
                                  floating_ip='10.0.1.10',
                                  http_status=exc.HTTPBadRequest.code)

    def test_create_floatingip_with_duplicated_specific_ip(self):

        with self.subnet(cidr='10.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            self._make_floatingip(self.fmt, network_id,
                                  floating_ip='10.0.0.10')

            self._make_floatingip(self.fmt, network_id,
                                  floating_ip='10.0.0.10',
                                  http_status=exc.HTTPConflict.code)

    def test_router_specify_id_backend(self):
        plugin = manager.NeutronManager.get_service_plugins()[
                    service_constants.L3_ROUTER_NAT]
        router_req = {'router': {'id': _uuid(), 'name': 'router',
                                 'admin_state_up': True}}
        result = plugin.create_router(context.Context('', 'foo'), router_req)
        self.assertEqual(result['id'], router_req['router']['id'])

    def test_create_floatingip_ipv6_only_network_returns_400(self):
        with self.subnet(cidr="2001:db8::/48", ip_version=6) as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._create_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'])
            self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4(self):
        with self.network() as n,\
                self.subnet(cidr="2001:db8::/48", ip_version=6, network=n),\
                self.subnet(cidr="192.168.1.0/24", ip_version=4, network=n):
            self._set_net_external(n['network']['id'])
            fip = self._make_floatingip(self.fmt, n['network']['id'])
            self.assertEqual(fip['floatingip']['floating_ip_address'],
                             '192.168.1.2')

    def test_create_floatingip_with_assoc_to_ipv6_subnet(self):
        with self.subnet() as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.subnet(cidr="2001:db8::/48",
                             ip_version=6) as private_sub:
                with self.port(subnet=private_sub) as private_port:
                    res = self._create_floatingip(
                        self.fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_floatingip_with_assoc_to_ipv4_and_ipv6_port(self):
        with self.network() as n,\
                self.subnet(cidr='10.0.0.0/24', network=n) as s4,\
                self.subnet(cidr='2001:db8::/64', ip_version=6, network=n),\
                self.port(subnet=s4) as p:
            self.assertEqual(len(p['port']['fixed_ips']), 2)
            ipv4_address = next(i['ip_address'] for i in
                    p['port']['fixed_ips'] if
                    netaddr.IPAddress(i['ip_address']).version == 4)
            with self.floatingip_with_assoc(port_id=p['port']['id']) as fip:
                self.assertEqual(fip['floatingip']['fixed_ip_address'],
                                 ipv4_address)
                floating_ip = netaddr.IPAddress(
                        fip['floatingip']['floating_ip_address'])
                self.assertEqual(floating_ip.version, 4)


class L3AgentDbTestCaseBase(L3NatTestCaseMixin):

    """Unit tests for methods called by the L3 agent."""

    def test_l3_agent_routers_query_interfaces(self):
        with self.router() as r:
            with self.port() as p:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              None,
                                              p['port']['id'])

                routers = self.plugin.get_sync_data(
                    context.get_admin_context(), None)
                self.assertEqual(1, len(routers))
                interfaces = routers[0][l3_constants.INTERFACE_KEY]
                self.assertEqual(1, len(interfaces))
                subnets = interfaces[0]['subnets']
                self.assertEqual(1, len(subnets))
                subnet_id = subnets[0]['id']
                wanted_subnetid = p['port']['fixed_ips'][0]['subnet_id']
                self.assertEqual(wanted_subnetid, subnet_id)

    def test_l3_agent_routers_query_ignore_interfaces_with_moreThanOneIp(self):
        with self.router() as r:
            with self.subnet(cidr='9.0.1.0/24') as subnet:
                with self.port(subnet=subnet,
                               fixed_ips=[{'ip_address': '9.0.1.3'}]) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    port = {'port': {'fixed_ips':
                                     [{'ip_address': '9.0.1.4',
                                       'subnet_id': subnet['subnet']['id']},
                                      {'ip_address': '9.0.1.5',
                                       'subnet_id': subnet['subnet']['id']}]}}
                    ctx = context.get_admin_context()
                    self.core_plugin.update_port(ctx, p['port']['id'], port)
                    routers = self.plugin.get_sync_data(ctx, None)
                    self.assertEqual(1, len(routers))
                    interfaces = routers[0].get(l3_constants.INTERFACE_KEY, [])
                    self.assertEqual(1, len(interfaces))

    def test_l3_agent_routers_query_gateway(self):
        with self.router() as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                routers = self.plugin.get_sync_data(
                    context.get_admin_context(), [r['router']['id']])
                self.assertEqual(1, len(routers))
                gw_port = routers[0]['gw_port']
                subnets = gw_port.get('subnets')
                self.assertEqual(1, len(subnets))
                self.assertEqual(s['subnet']['id'], subnets[0]['id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])

    def test_l3_agent_routers_query_floatingips(self):
        with self.floatingip_with_assoc() as fip:
            routers = self.plugin.get_sync_data(
                context.get_admin_context(), [fip['floatingip']['router_id']])
            self.assertEqual(1, len(routers))
            floatingips = routers[0][l3_constants.FLOATINGIP_KEY]
            self.assertEqual(1, len(floatingips))
            self.assertEqual(floatingips[0]['id'],
                             fip['floatingip']['id'])
            self.assertEqual(floatingips[0]['port_id'],
                             fip['floatingip']['port_id'])
            self.assertIsNotNone(floatingips[0]['fixed_ip_address'])
            self.assertIsNotNone(floatingips[0]['router_id'])

    def _test_notify_op_agent(self, target_func, *args):
        l3_rpc_agent_api_str = (
            'neutron.api.rpc.agentnotifiers.l3_rpc_agent_api.L3AgentNotifyAPI')
        with mock.patch(l3_rpc_agent_api_str):
            plugin = manager.NeutronManager.get_service_plugins()[
                service_constants.L3_ROUTER_NAT]
            notifyApi = plugin.l3_rpc_notifier
            kargs = [item for item in args]
            kargs.append(notifyApi)
            target_func(*kargs)

    def _test_router_gateway_op_agent(self, notifyApi):
        with self.router() as r:
            with self.subnet() as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                self.assertEqual(
                    2, notifyApi.routers_updated.call_count)

    def test_router_gateway_op_agent(self):
        self._test_notify_op_agent(self._test_router_gateway_op_agent)

    def _test_interfaces_op_agent(self, r, notifyApi):
        with self.port() as p:
            self._router_interface_action('add',
                                          r['router']['id'],
                                          None,
                                          p['port']['id'])
            # clean-up
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          None,
                                          p['port']['id'])
        self.assertEqual(2, notifyApi.routers_updated.call_count)

    def test_interfaces_op_agent(self):
        with self.router() as r:
            self._test_notify_op_agent(
                self._test_interfaces_op_agent, r)

    def _test_floatingips_op_agent(self, notifyApi):
        with self.floatingip_with_assoc():
            pass
        # add gateway, add interface, associate, deletion of floatingip
        self.assertEqual(4, notifyApi.routers_updated.call_count)

    def test_floatingips_op_agent(self):
        self._test_notify_op_agent(self._test_floatingips_op_agent)


class L3BaseForIntTests(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    mock_rescheduling = True

    def setUp(self, plugin=None, ext_mgr=None, service_plugins=None):
        if not plugin:
            plugin = 'neutron.tests.unit.extensions.test_l3.TestL3NatIntPlugin'
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        ext_mgr = ext_mgr or L3TestExtensionManager()

        if self.mock_rescheduling:
            mock.patch('%s._check_router_needs_rescheduling' % plugin,
                       new=lambda *a: False).start()

        super(L3BaseForIntTests, self).setUp(plugin=plugin, ext_mgr=ext_mgr,
                                             service_plugins=service_plugins)

        self.setup_notification_driver()


class L3BaseForSepTests(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=None, ext_mgr=None):
        # the plugin without L3 support
        if not plugin:
            plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        if not ext_mgr:
            ext_mgr = L3TestExtensionManager()
        super(L3BaseForSepTests, self).setUp(plugin=plugin, ext_mgr=ext_mgr,
                                             service_plugins=service_plugins)

        self.setup_notification_driver()


class L3NatDBIntAgentSchedulingTestCase(L3BaseForIntTests,
                                        L3NatTestCaseMixin,
                                        test_agent.
                                        AgentDBTestMixIn):

    """Unit tests for core plugin with L3 routing and scheduling integrated."""

    def setUp(self, plugin='neutron.tests.unit.extensions.test_l3.'
                           'TestL3NatIntAgentSchedulingPlugin',
              ext_mgr=None, service_plugins=None):
        self.mock_rescheduling = False
        super(L3NatDBIntAgentSchedulingTestCase, self).setUp(
            plugin, ext_mgr, service_plugins)
        self.adminContext = context.get_admin_context()

    def _assert_router_on_agent(self, router_id, agent_host):
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        agents = plugin.list_l3_agents_hosting_router(
            self.adminContext, router_id)['agents']
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]['host'], agent_host)

    def test_update_gateway_agent_exists_supporting_network(self):
        with self.router() as r, self.subnet() as s1, self.subnet() as s2:
            self._set_net_external(s1['subnet']['network_id'])
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            helpers.register_l3_agent(
                host='host1',
                ext_net_id=s1['subnet']['network_id'])
            helpers.register_l3_agent(
                host='host2', internal_only=False,
                ext_net_id=s2['subnet']['network_id'])
            l3_rpc_cb.sync_routers(self.adminContext,
                                   host='host1')
            self._assert_router_on_agent(r['router']['id'], 'host1')

            self._add_external_gateway_to_router(
                r['router']['id'],
                s1['subnet']['network_id'])
            self._assert_router_on_agent(r['router']['id'], 'host1')

            self._set_net_external(s2['subnet']['network_id'])
            self._add_external_gateway_to_router(
                r['router']['id'],
                s2['subnet']['network_id'])
            self._assert_router_on_agent(r['router']['id'], 'host2')

    def test_update_gateway_agent_exists_supporting_multiple_network(self):
        with self.router() as r, self.subnet() as s1, self.subnet() as s2:
            self._set_net_external(s1['subnet']['network_id'])
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            helpers.register_l3_agent(
                host='host1',
                ext_net_id=s1['subnet']['network_id'])
            helpers.register_l3_agent(
                host='host2', internal_only=False,
                ext_net_id='', ext_bridge='')
            l3_rpc_cb.sync_routers(self.adminContext,
                                   host='host1')
            self._assert_router_on_agent(r['router']['id'], 'host1')

            self._add_external_gateway_to_router(
                r['router']['id'],
                s1['subnet']['network_id'])
            self._assert_router_on_agent(r['router']['id'], 'host1')

            self._set_net_external(s2['subnet']['network_id'])
            self._add_external_gateway_to_router(
                r['router']['id'],
                s2['subnet']['network_id'])
            self._assert_router_on_agent(r['router']['id'], 'host2')

    def test_router_update_gateway_no_eligible_l3_agent(self):
        with self.router() as r:
            with self.subnet() as s1:
                with self.subnet() as s2:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._set_net_external(s2['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'],
                        expected_code=exc.HTTPBadRequest.code)


class L3RpcCallbackTestCase(base.BaseTestCase):

    def setUp(self):
        super(L3RpcCallbackTestCase, self).setUp()
        self.mock_plugin = mock.patch.object(
            l3_rpc.L3RpcCallback,
            'plugin', new_callable=mock.PropertyMock).start()
        self.mock_l3plugin = mock.patch.object(
            l3_rpc.L3RpcCallback,
            'l3plugin', new_callable=mock.PropertyMock).start()
        self.l3_rpc_cb = l3_rpc.L3RpcCallback()

    def test__ensure_host_set_on_port_host_id_none(self):
        port = {'id': 'id', portbindings.HOST_ID: 'somehost'}
        self.l3_rpc_cb._ensure_host_set_on_port(None, None, port)
        self.assertFalse(self.l3_rpc_cb.plugin.update_port.called)

    def test__ensure_host_set_on_port_update_on_concurrent_delete(self):
        port_id = 'foo_port_id'
        port = {
            'id': port_id,
            'device_owner': 'compute:None',
            portbindings.HOST_ID: '',
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_BINDING_FAILED
        }
        router_id = 'foo_router_id'
        self.l3_rpc_cb.plugin.update_port.side_effect = n_exc.PortNotFound(
            port_id=port_id)
        with mock.patch.object(l3_rpc.LOG, 'debug') as mock_log:
            self.l3_rpc_cb._ensure_host_set_on_port(
                mock.ANY, mock.ANY, port, router_id)
        self.l3_rpc_cb.plugin.update_port.assert_called_once_with(
            mock.ANY, port_id, {'port': {'binding:host_id': mock.ANY}})
        self.assertTrue(mock_log.call_count)
        expected_message = ('Port foo_port_id not found while updating '
                            'agent binding for router foo_router_id.')
        actual_message = mock_log.call_args[0][0] % mock_log.call_args[0][1]
        self.assertEqual(expected_message, actual_message)


class L3AgentDbIntTestCase(L3BaseForIntTests, L3AgentDbTestCaseBase):

    """Unit tests for methods called by the L3 agent for
    the case where core plugin implements L3 routing.
    """

    def setUp(self):
        super(L3AgentDbIntTestCase, self).setUp()
        self.core_plugin = TestL3NatIntPlugin()
        self.plugin = self.core_plugin


class L3AgentDbSepTestCase(L3BaseForSepTests, L3AgentDbTestCaseBase):

    """Unit tests for methods called by the L3 agent for the
    case where separate service plugin implements L3 routing.
    """

    def setUp(self):
        super(L3AgentDbSepTestCase, self).setUp()
        self.core_plugin = TestNoL3NatPlugin()
        self.plugin = TestL3NatServicePlugin()


class L3NatDBIntTestCase(L3BaseForIntTests, L3NatTestCaseBase):

    """Unit tests for core plugin with L3 routing integrated."""
    pass


class L3NatDBSepTestCase(L3BaseForSepTests, L3NatTestCaseBase):

    """Unit tests for a separate L3 routing service plugin."""

    def test_port_deletion_prevention_handles_missing_port(self):
        pl = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        self.assertIsNone(
            pl.prevent_l3_port_deletion(context.get_admin_context(), 'fakeid')
        )
