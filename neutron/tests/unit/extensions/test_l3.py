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
from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib import context
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.tests.unit import fake_notifier
from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import uuidutils
from sqlalchemy import orm
import testtools
from webob import exc

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.db import db_base_plugin_v2
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import l3_dvr_db
from neutron.db import l3_dvrscheduler_db
from neutron.db import l3_hamode_db
from neutron.db.models import l3 as l3_models
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.services.revisions import revision_plugin
from neutron.tests import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import base as test_extensions_base
from neutron.tests.unit.extensions import test_agent
from neutron.tests.unit.plugins.ml2 import base as ml2_base
from neutron.tests.unit import testlib_api


_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


DEVICE_OWNER_COMPUTE = lib_constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class L3TestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3NatExtensionTestCase(test_extensions_base.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(L3NatExtensionTestCase, self).setUp()
        self.setup_extension(
            'neutron.services.l3_router.l3_router_plugin.L3RouterPlugin',
            plugin_constants.L3, l3.L3, '', allow_pagination=True,
            allow_sorting=True, supported_extension_aliases=['router'],
            use_quota=True)

    def test_router_create(self):
        router_id = _uuid()
        tenant_id = _uuid()
        data = {'router': {'name': 'router1', 'admin_state_up': True,
                           'tenant_id': tenant_id, 'project_id': tenant_id,
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
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('router', res)
        router = res['router']
        self.assertEqual(router_id, router['id'])
        self.assertEqual("ACTIVE", router['status'])
        self.assertTrue(router['admin_state_up'])

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
        self.assertEqual(exc.HTTPOk.code, res.status_int)
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
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('router', res)
        router = res['router']
        self.assertEqual(router_id, router['id'])
        self.assertEqual("ACTIVE", router['status'])
        self.assertFalse(router['admin_state_up'])

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
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('router', res)
        router = res['router']
        self.assertEqual(router_id, router['id'])
        self.assertEqual("ACTIVE", router['status'])
        self.assertFalse(router['admin_state_up'])

    def test_router_delete(self):
        router_id = _uuid()

        res = self.api.delete(_get_path('routers', id=router_id))

        instance = self.plugin.return_value
        instance.delete_router.assert_called_with(mock.ANY, router_id)
        self.assertEqual(exc.HTTPNoContent.code, res.status_int)

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
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_id', res)
        self.assertEqual(port_id, res['port_id'])
        self.assertEqual(subnet_id, res['subnet_id'])

    def test_router_add_interface_empty_body(self):
        router_id = _uuid()
        instance = self.plugin.return_value

        path = _get_path('routers', id=router_id,
                         action="add_router_interface",
                         fmt=self.fmt)
        res = self.api.put(path)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        instance.add_router_interface.assert_called_with(mock.ANY, router_id)


class TestL3PluginBaseAttributes(object):

    IP_UPDATE_NOT_ALLOWED_LIST = [
        lib_constants.DEVICE_OWNER_ROUTER_INTF,
        lib_constants.DEVICE_OWNER_ROUTER_HA_INTF,
        lib_constants.DEVICE_OWNER_HA_REPLICATED_INT,
        lib_constants.DEVICE_OWNER_ROUTER_SNAT,
        lib_constants.DEVICE_OWNER_DVR_INTERFACE]

    def router_supports_scheduling(self, context, router_id):
        return True


# This base plugin class is for tests.
class TestL3NatBasePlugin(TestL3PluginBaseAttributes,
                          db_base_plugin_v2.NeutronDbPluginV2,
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

    def delete_port(self, context, id, l3_port_check=True):
        plugin = directory.get_plugin(plugin_constants.L3)
        if plugin:
            if l3_port_check:
                plugin.prevent_l3_port_deletion(context, id)
            plugin.disassociate_floatingips(context, id)
        return super(TestL3NatBasePlugin, self).delete_port(context, id)

    def update_port(self, context, id, port):
        original_port = self.get_port(context, id)
        session = context.session
        with session.begin(subtransactions=True):
            new_port = super(TestL3NatBasePlugin, self).update_port(
                context, id, port)
        # Notifications must be sent after the above transaction is complete
        kwargs = {
            'context': context,
            'port': new_port,
            'original_port': original_port,
        }
        registry.notify(resources.PORT, events.AFTER_UPDATE, self, **kwargs)
        return new_port


# This plugin class is for tests with plugin that integrates L3.
class TestL3NatIntPlugin(TestL3NatBasePlugin,
                         l3_db.L3_NAT_db_mixin, dns_db.DNSDbMixin):

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = [extnet_apidef.ALIAS, l3_apidef.ALIAS,
                                   dns_apidef.ALIAS]


# This plugin class is for tests with plugin that integrates L3 and L3 agent
# scheduling.
class TestL3NatIntAgentSchedulingPlugin(TestL3NatIntPlugin,
                                        l3_agentschedulers_db.
                                        L3AgentSchedulerDbMixin,
                                        l3_hamode_db.L3_HA_NAT_db_mixin):

    supported_extension_aliases = [extnet_apidef.ALIAS, l3_apidef.ALIAS,
                                   lib_constants.L3_AGENT_SCHEDULER_EXT_ALIAS]
    router_scheduler = importutils.import_object(
        cfg.CONF.router_scheduler_driver)


# This plugin class is for tests with plugin not supporting L3.
class TestNoL3NatPlugin(TestL3NatBasePlugin):

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = [extnet_apidef.ALIAS]


# A L3 routing service plugin class for tests with plugins that
# delegate away L3 routing functionality
class TestL3NatServicePlugin(TestL3PluginBaseAttributes,
                             l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                             l3_db.L3_NAT_db_mixin, dns_db.DNSDbMixin):

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = [l3_apidef.ALIAS, dns_apidef.ALIAS]

    @classmethod
    def get_plugin_type(cls):
        return plugin_constants.L3

    def get_plugin_description(self):
        return "L3 Routing Service Plugin for testing"


# A L3 routing with L3 agent scheduling service plugin class for tests with
# plugins that delegate away L3 routing functionality
class TestL3NatAgentSchedulingServicePlugin(TestL3NatServicePlugin,
                                            l3_dvrscheduler_db.
                                            L3_DVRsch_db_mixin,
                                            l3_hamode_db.L3_HA_NAT_db_mixin):

    supported_extension_aliases = [l3_apidef.ALIAS,
                                   lib_constants.L3_AGENT_SCHEDULER_EXT_ALIAS]

    def __init__(self):
        super(TestL3NatAgentSchedulingServicePlugin, self).__init__()
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        self.agent_notifiers.update(
            {lib_constants.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})


class L3NatTestCaseMixin(object):

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up is not None:
            data['router']['admin_state_up'] = admin_state_up
        flavor_id = kwargs.get('flavor_id', None)
        if flavor_id:
            data['router']['flavor_id'] = flavor_id
        for arg in (('admin_state_up', 'tenant_id',
                     'availability_zone_hints') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs:
                data['router'][arg] = kwargs[arg]
        if 'distributed' in kwargs:
            data['router']['distributed'] = bool(kwargs['distributed'])
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
                                        neutron_context=None, ext_ips=None,
                                        **kwargs):
        ext_ips = ext_ips or []
        body = {'router':
                {'external_gateway_info': {'network_id': network_id}}}
        if ext_ips:
            body['router']['external_gateway_info'][
                'external_fixed_ips'] = ext_ips
        if 'policy_id' in kwargs:
            body['router']['external_gateway_info'][
                'qos_policy_id'] = kwargs.get('policy_id')
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
        if subnet_id is not None:
            interface_data.update({'subnet_id': subnet_id})
        if port_id is not None:
            interface_data.update({'port_id': port_id})

        req = self.new_action_request('routers', interface_data, router_id,
                                      "%s_router_interface" % action)
        # if tenant_id was specified, create a tenant context for this request
        if tenant_id:
            req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int, msg)
        response = self.deserialize(self.fmt, res)
        if expected_body:
            self.assertEqual(expected_body, response, msg)
        return response

    @contextlib.contextmanager
    def router(self, name='router1', admin_state_up=True,
               fmt=None, tenant_id=None,
               external_gateway_info=None, set_context=False,
               **kwargs):
        router = self._make_router(fmt or self.fmt, tenant_id, name,
                                   admin_state_up, external_gateway_info,
                                   set_context, **kwargs)
        yield router

    def _set_net_external(self, net_id):
        self._update('networks', net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}})

    def _create_floatingip(self, fmt, network_id, port_id=None,
                           fixed_ip=None, set_context=False,
                           floating_ip=None, subnet_id=None,
                           tenant_id=None, **kwargs):
        tenant_id = tenant_id or self._tenant_id
        data = {'floatingip': {'floating_network_id': network_id,
                               'tenant_id': tenant_id}}
        if port_id:
            data['floatingip']['port_id'] = port_id
            if fixed_ip:
                data['floatingip']['fixed_ip_address'] = fixed_ip

        if floating_ip:
            data['floatingip']['floating_ip_address'] = floating_ip

        if subnet_id:
            data['floatingip']['subnet_id'] = subnet_id

        data['floatingip'].update(kwargs)

        floatingip_req = self.new_create_request('floatingips', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            floatingip_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return floatingip_req.get_response(self.ext_api)

    def _make_floatingip(self, fmt, network_id, port_id=None,
                         fixed_ip=None, set_context=False, tenant_id=None,
                         floating_ip=None, http_status=exc.HTTPCreated.code,
                         **kwargs):
        res = self._create_floatingip(fmt, network_id, port_id,
                                      fixed_ip, set_context, floating_ip,
                                      tenant_id=tenant_id, **kwargs)
        self.assertEqual(http_status, res.status_int)
        return self.deserialize(fmt, res)

    def _validate_floating_ip(self, fip):
        body = self._list('floatingips')
        self.assertEqual(1, len(body['floatingips']))
        self.assertEqual(body['floatingips'][0]['id'],
                         fip['floatingip']['id'])

        body = self._show('floatingips', fip['floatingip']['id'])
        self.assertEqual(body['floatingip']['id'],
                         fip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_with_assoc(self, port_id=None, fmt=None, fixed_ip=None,
                              public_cidr='11.0.0.0/24', set_context=False,
                              tenant_id=None, flavor_id=None, **kwargs):
        with self.subnet(cidr=public_cidr,
                         set_context=set_context,
                         tenant_id=tenant_id) as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            args_list = {'set_context': set_context,
                         'tenant_id': tenant_id}
            if flavor_id:
                args_list['flavor_id'] = flavor_id
            private_port = None
            if port_id:
                private_port = self._show('ports', port_id)
            with test_db_base_plugin_v2.optional_ctx(
                    private_port, self.port,
                    set_context=set_context,
                    tenant_id=tenant_id) as private_port:
                with self.router(**args_list) as r:
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
                        tenant_id=tenant_id,
                        set_context=set_context,
                        **kwargs)
                    yield floatingip

                    if floatingip:
                        self._delete('floatingips',
                                     floatingip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_no_assoc_with_public_sub(self, private_sub, fmt=None,
                                            set_context=False, public_sub=None,
                                            flavor_id=None, **kwargs):
        self._set_net_external(public_sub['subnet']['network_id'])
        args_list = {}
        if flavor_id:
            # NOTE(manjeets) Flavor id None is not accepted
            # and return Flavor None not found error. So for
            # neutron testing this argument should not be passed
            # at all to router.
            args_list['flavor_id'] = flavor_id
        with self.router(**args_list) as r:
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
                set_context=set_context,
                **kwargs)
            yield floatingip, r

            if floatingip:
                self._delete('floatingips',
                             floatingip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_no_assoc(self, private_sub, fmt=None,
                            set_context=False, flavor_id=None, **kwargs):
        with self.subnet(cidr='12.0.0.0/24') as public_sub:
            with self.floatingip_no_assoc_with_public_sub(
                    private_sub, fmt, set_context, public_sub,
                    flavor_id, **kwargs) as (f, r):
                # Yield only the floating ip object
                yield f


class ExtraAttributesMixinTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(ExtraAttributesMixinTestCase, self).setUp()
        self.mixin = l3_attrs_db.ExtraAttributesMixin()
        directory.add_plugin(plugin_constants.L3, self.mixin)
        self.ctx = context.get_admin_context()
        self.router = l3_models.Router()
        with self.ctx.session.begin():
            self.ctx.session.add(self.router)

    def _get_default_api_values(self):
        return {k: v.get('transform_from_db', lambda x: x)(v['default'])
                for k, v in l3_attrs_db.get_attr_info().items()}

    def test_set_extra_attr_key_bad(self):
        with testtools.ExpectedException(RuntimeError):
            with self.ctx.session.begin():
                self.mixin.set_extra_attr_value(self.ctx, self.router,
                                                'bad', 'value')

    def test_set_attrs_and_extend_no_transaction(self):
        with testtools.ExpectedException(RuntimeError):
            self.mixin.set_extra_attr_value(self.ctx, self.router,
                                            'ha_vr_id', 99)

    def test__extend_extra_router_dict_defaults(self):
        rdict = {}
        self.mixin._extend_extra_router_dict(rdict, self.router)
        self.assertEqual(self._get_default_api_values(), rdict)

    def test_set_attrs_and_extend(self):
        with self.ctx.session.begin():
            self.mixin.set_extra_attr_value(self.ctx, self.router,
                                            'ha_vr_id', 99)
            self.mixin.set_extra_attr_value(self.ctx, self.router,
                                            'availability_zone_hints',
                                            ['x', 'y', 'z'])
        expected = self._get_default_api_values()
        expected.update({'ha_vr_id': 99,
                         'availability_zone_hints': ['x', 'y', 'z']})
        rdict = {}
        self.mixin._extend_extra_router_dict(rdict, self.router)
        self.assertEqual(expected, rdict)
        with self.ctx.session.begin():
            self.mixin.set_extra_attr_value(self.ctx, self.router,
                                            'availability_zone_hints',
                                            ['z', 'y', 'z'])
        expected['availability_zone_hints'] = ['z', 'y', 'z']
        self.mixin._extend_extra_router_dict(rdict, self.router)
        self.assertEqual(expected, rdict)


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

        resource_extend.register_funcs(
            l3_apidef.ROUTERS, [_extend_router_dict_test_attr])
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
            self.assertEqual(exc.HTTPForbidden.code, res.status_int)

    def test_create_routers_native_quotas(self):
        tenant_id = _uuid()
        quota = 1
        cfg.CONF.set_override('quota_router', quota, group='QUOTAS')
        res = self._create_router(self.fmt, tenant_id)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self._create_router(self.fmt, tenant_id)
        self.assertEqual(exc.HTTPConflict.code, res.status_int)

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
                    self.subnet(network=n,
                                ip_version=lib_constants.IP_VERSION_6,
                                cidr='2001:db8::/32') \
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

    def test_router_concurrent_delete_upon_subnet_create(self):
        with self.network() as n:
            with self.subnet(network=n) as s1, self.router() as r:
                self._set_net_external(n['network']['id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    n['network']['id'],
                    ext_ips=[{'subnet_id': s1['subnet']['id']}])
                plugin = directory.get_plugin(plugin_constants.L3)
                mock.patch.object(
                    plugin, 'update_router',
                    side_effect=l3_exc.RouterNotFound(router_id='1')).start()
                # ensure the router disappearing doesn't interfere with subnet
                # creation
                self._create_subnet(self.fmt, net_id=n['network']['id'],
                                    ip_version=lib_constants.IP_VERSION_6,
                                    cidr='2001:db8::/32',
                                    expected_res_status=(exc.HTTPCreated.code))

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
                                         ip_version=lib_constants.IP_VERSION_6,
                                         cidr='2001:db8::/32',
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
                    self.subnet(ip_version=lib_constants.IP_VERSION_6,
                        cidr='2001:db8::/64',
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
                            ip_version=lib_constants.IP_VERSION_6,
                            cidr='2001:db8:1::/64',
                            ipv6_ra_mode=lib_constants.IPV6_SLAAC,
                            ipv6_address_mode=lib_constants.IPV6_SLAAC))
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
                rtid = router['router']['tenant_id']
                # tolerate subnet tenant deliberately set to '' in the
                # nsx metadata access case
                self.assertIn(payload['tenant_id'], [rtid, ''], msg)

    def test_router_add_interface_bad_values(self):
        with self.router() as r:
            exp_code = exc.HTTPBadRequest.code
            self._router_interface_action('add',
                                          r['router']['id'],
                                          False,
                                          None,
                                          expected_code=exp_code)
            self._router_interface_action('add',
                                          r['router']['id'],
                                          None,
                                          False,
                                          expected_code=exp_code)

    def test_router_add_interface_subnet(self):
        fake_notifier.reset()
        with self.router() as r:
            with self.network() as n:
                with self.subnet(network=n) as s:
                    self._test_router_add_interface_subnet(r, s)

    def test_router_delete_race_with_interface_add(self):
        # this test depends on protection from the revision plugin so
        # we have to initialize it
        revision_plugin.RevisionPlugin()
        with self.router() as r, self.subnet() as s:

            def jam_in_interface(*args, **kwargs):
                self._router_interface_action('add', r['router']['id'],
                                              s['subnet']['id'], None)
                # unsubscribe now that the evil is done
                registry.unsubscribe(jam_in_interface, resources.ROUTER,
                                     events.PRECOMMIT_DELETE)
            registry.subscribe(jam_in_interface, resources.ROUTER,
                               events.PRECOMMIT_DELETE)
            self._delete('routers', r['router']['id'],
                         expected_code=exc.HTTPConflict.code)

    def test_router_add_interface_ipv6_subnet(self):
        """Test router-interface-add for valid ipv6 subnets.

        Verify the valid use-cases of an IPv6 subnet where we
        are allowed to associate to the Neutron Router are successful.
        """
        slaac = lib_constants.IPV6_SLAAC
        stateful = lib_constants.DHCPV6_STATEFUL
        stateless = lib_constants.DHCPV6_STATELESS
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
                                 gateway_ip='fd00::1',
                                 ip_version=lib_constants.IP_VERSION_6,
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
            with (self.subnet(network=n, cidr='fd00::1/64',
                              ip_version=lib_constants.IP_VERSION_6)
                  ) as s1, self.subnet(network=n, cidr='fd01::1/64',
                                       ip_version=lib_constants.IP_VERSION_6
                                       ) as s2:
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
            with (self.subnet(network=n1, cidr='fd00::1/64',
                              ip_version=lib_constants.IP_VERSION_6)
                  ) as s1, self.subnet(network=n2, cidr='fd01::1/64',
                                       ip_version=lib_constants.IP_VERSION_6
                                       ) as s2:
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
                      'address_mode': lib_constants.IPV6_SLAAC},
                     {'msg': 'IPv6 Subnet Modes (none, dhcpv6-stateful)',
                      'ra_mode': None,
                      'address_mode': lib_constants.DHCPV6_STATEFUL},
                     {'msg': 'IPv6 Subnet Modes (none, dhcpv6-stateless)',
                      'ra_mode': None,
                      'address_mode': lib_constants.DHCPV6_STATELESS}]
        for uc in use_cases:
            with self.router() as r, self.network() as n:
                with self.subnet(network=n, cidr='fd00::1/64',
                                 gateway_ip='fd00::1',
                                 ip_version=lib_constants.IP_VERSION_6,
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
            with self.subnet(ip_version=lib_constants.IP_VERSION_6,
                             cidr='fe80::/64',
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

    def test_router_add_interface_by_subnet_other_tenant_subnet_returns_400(
            self):
        router_tenant_id = _uuid()
        with self.router(tenant_id=router_tenant_id, set_context=True) as r:
            with self.network(shared=True) as n:
                with self.subnet(network=n) as s:
                    err_code = exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  None,
                                                  expected_code=err_code,
                                                  tenant_id=router_tenant_id)

    def _test_router_add_interface_by_port_allocation_pool(
            self, out_of_pool=False, router_action_as_admin=False,
            expected_code=exc.HTTPOk.code):
        router_tenant_id = _uuid()
        with self.router(tenant_id=router_tenant_id, set_context=True) as r:
            with self.network(shared=True) as n:
                with self.subnet(network=n) as s1, (
                     self.subnet(network=n, cidr='fd00::/64',
                                 ip_version=lib_constants.IP_VERSION_6)
                                 ) as s2, (
                     self.subnet(network=n, cidr='fd01::/64',
                                 ip_version=lib_constants.IP_VERSION_6)
                                 ) as s3:
                    fixed_ips = [{'subnet_id': s1['subnet']['id']},
                                 {'subnet_id': s2['subnet']['id']},
                                 {'subnet_id': s3['subnet']['id']}]
                    if out_of_pool:
                        fixed_ips[1] = {'subnet_id': s2['subnet']['id'],
                                        'ip_address':
                                            s2['subnet']['gateway_ip']}
                    with self.port(subnet=s1, fixed_ips=fixed_ips,
                                   tenant_id=router_tenant_id) as p:
                        kwargs = {'expected_code': expected_code}
                        if not router_action_as_admin:
                            kwargs['tenant_id'] = router_tenant_id
                        self._router_interface_action(
                            'add', r['router']['id'], None, p['port']['id'],
                            **kwargs)

    def test_router_add_interface_by_port_other_tenant_address_in_pool(
            self):
        self._test_router_add_interface_by_port_allocation_pool()

    def test_router_add_interface_by_port_other_tenant_address_out_of_pool(
            self):
        self._test_router_add_interface_by_port_allocation_pool(
            out_of_pool=True, expected_code=exc.HTTPBadRequest.code)

    def test_router_add_interface_by_port_admin_address_out_of_pool(
            self):
        self._test_router_add_interface_by_port_allocation_pool(
            out_of_pool=True, router_action_as_admin=True)

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
        orig_update_port = self.plugin.update_port
        with self.router() as r, (
            self.port()) as p, (
                mock.patch.object(self.plugin, 'update_port')) as update_port:
            update_port.side_effect = orig_update_port
            body = self._router_interface_action('add',
                                                 r['router']['id'],
                                                 None,
                                                 p['port']['id'])
            self.assertIn('port_id', body)
            self.assertEqual(p['port']['id'], body['port_id'])
            expected_port_update = {
                'device_owner': lib_constants.DEVICE_OWNER_ROUTER_INTF,
                'device_id': r['router']['id']}
            update_port.assert_any_call(
                mock.ANY, p['port']['id'], {'port': expected_port_update})
            # fetch port and confirm device_id
            body = self._show('ports', p['port']['id'])
            self.assertEqual(r['router']['id'], body['port']['device_id'])

            # clean-up
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          None,
                                          p['port']['id'])

    def test_update_router_interface_port_ip_not_allowed(self):
        with self.router() as r, self.port() as p:
            body = self._router_interface_action('add',
                                                 r['router']['id'],
                                                 None,
                                                 p['port']['id'])
            self.assertIn('port_id', body)
            self.assertEqual(p['port']['id'], body['port_id'])
            body = self._show('ports', p['port']['id'])
            self.assertEqual(r['router']['id'], body['port']['device_id'])

            data = {'port': {'fixed_ips': [
                {'ip_address': '1.1.1.1'},
                {'ip_address': '2.2.2.2'}]}}
            self._update('ports', p['port']['id'], data,
                         neutron_context=context.get_admin_context(),
                         expected_code=exc.HTTPBadRequest.code)

            self._router_interface_action('remove',
                                          r['router']['id'],
                                          None,
                                          p['port']['id'])

    def test_router_add_interface_delete_port_after_failure(self):
        with self.router() as r, self.subnet(enable_dhcp=False) as s:
            plugin = directory.get_plugin()
            # inject a failure in the update port that happens at the end
            # to ensure the port gets deleted
            with mock.patch.object(
                    plugin, 'update_port',
                    side_effect=n_exc.InvalidInput(error_message='x')):
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None,
                                              exc.HTTPBadRequest.code)
                self.assertFalse(plugin.get_ports(context.get_admin_context()))

    def test_router_add_interface_dup_port(self):
        '''This tests that if multiple routers add one port as their
        interfaces. Only the first router's interface would be added
        to this port. All the later requests would return exceptions.
        '''
        with self.router() as r1, self.router() as r2, self.network() as n:
            with self.subnet(network=n) as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r1['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # mock out the sequential check
                    plugin = 'neutron.db.l3_db.L3_NAT_dbonly_mixin'
                    check_p = mock.patch(plugin + '._check_router_port',
                                         port_id=p['port']['id'],
                                         device_id=r2['router']['id'],
                                         return_value=p['port'])
                    checkport = check_p.start()
                    # do regular checkport after first skip
                    checkport.side_effect = check_p.stop()
                    self._router_interface_action('add',
                                                  r2['router']['id'],
                                                  None,
                                                  p['port']['id'],
                                                  exc.HTTPConflict.code)
                    # clean-up
                    self._router_interface_action('remove',
                                                  r1['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_update_router_interface_port_ipv6_subnet_ext_ra(self):
        use_cases = [{'msg': 'IPv6 Subnet Modes (none, slaac)',
                      'ra_mode': None,
                      'address_mode': lib_constants.IPV6_SLAAC},
                     {'msg': 'IPv6 Subnet Modes (none, dhcpv6-stateful)',
                      'ra_mode': None,
                      'address_mode': lib_constants.DHCPV6_STATEFUL},
                     {'msg': 'IPv6 Subnet Modes (none, dhcpv6-stateless)',
                      'ra_mode': None,
                      'address_mode': lib_constants.DHCPV6_STATELESS}]
        for uc in use_cases:
            with self.network() as network, self.router() as router:
                with self.subnet(
                        network=network, cidr='fd00::/64',
                        ip_version=lib_constants.IP_VERSION_6,
                        ipv6_ra_mode=uc['ra_mode'],
                        ipv6_address_mode=uc['address_mode']) as subnet:
                    fixed_ips = [{'subnet_id': subnet['subnet']['id']}]
                    with self.port(subnet=subnet, fixed_ips=fixed_ips) as port:
                        self._router_interface_action(
                            'add',
                            router['router']['id'],
                            None,
                            port['port']['id'],
                            expected_code=exc.HTTPBadRequest.code,
                            msg=uc['msg'])

    def _assert_body_port_id_and_update_port(self, body, mock_update_port,
                                             port_id, device_id):
        self.assertNotIn('port_id', body)
        expected_port_update_before_update = {
            'device_owner': lib_constants.DEVICE_OWNER_ROUTER_INTF,
            'device_id': device_id}
        expected_port_update_after_fail = {
            'device_owner': '',
            'device_id': ''}
        mock_update_port.assert_has_calls(
            [mock.call(
                mock.ANY,
                port_id,
                {'port': expected_port_update_before_update}),
             mock.call(
                mock.ANY,
                port_id,
                {'port': expected_port_update_after_fail})],
            any_order=False)
        # fetch port and confirm device_id and device_owner
        body = self._show('ports', port_id)
        self.assertEqual('', body['port']['device_owner'])
        self.assertEqual('', body['port']['device_id'])

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
                orig_update_port = self.plugin.update_port
                with self.port(subnet=s1, fixed_ips=fixed_ips) as p, (
                        mock.patch.object(self.plugin,
                                          'update_port')) as update_port:
                    update_port.side_effect = orig_update_port
                    exp_code = exc.HTTPBadRequest.code
                    body = self._router_interface_action(
                        'add', r['router']['id'], None, p['port']['id'],
                        expected_code=exp_code)
                    self._assert_body_port_id_and_update_port(
                        body, update_port, p['port']['id'], r['router']['id'])

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        """Ensure unique IPv6 router ports per network id.

        Adding a router port containing one or more IPv6 subnets with the same
        network id as an existing router port should fail. This is so
        there is no ambiguity regarding on which port to add an IPv6 subnet
        when executing router-interface-add with a subnet and no port.
        """
        with self.network() as n, self.router() as r:
            with self.subnet(network=n, cidr='fd00::/64',
                             ip_version=lib_constants.IP_VERSION_6) as s1, (
                 self.subnet(network=n, cidr='fd01::/64',
                             ip_version=lib_constants.IP_VERSION_6)) as s2:
                orig_update_port = self.plugin.update_port
                with self.port(subnet=s1) as p, (
                        mock.patch.object(self.plugin,
                                          'update_port')) as update_port:
                    update_port.side_effect = orig_update_port
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    exp_code = exc.HTTPBadRequest.code
                    body = self._router_interface_action(
                        'add', r['router']['id'], None, p['port']['id'],
                        expected_code=exp_code)
                    self._assert_body_port_id_and_update_port(
                        body, update_port, p['port']['id'], r['router']['id'])
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
                             ip_version=lib_constants.IP_VERSION_6) as s1, (
                 self.subnet(network=n, cidr='fd01::/64',
                             ip_version=lib_constants.IP_VERSION_6)) as s2:
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
                device_owner=lib_constants.DEVICE_OWNER_ROUTER_INTF)
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
            with self.subnet() as s1, self.subnet(cidr='1.0.0.0/24') as s2:
                with self.port(subnet=s1) as p1, self.port(subnet=s2) as p2:
                    orig_update_port = self.plugin.update_port
                    with self.port(subnet=s1) as p3, (
                        mock.patch.object(self.plugin,
                                          'update_port')) as update_port:
                        update_port.side_effect = orig_update_port
                        for p in [p1, p2]:
                            self._router_interface_action('add',
                                                          r['router']['id'],
                                                          None,
                                                          p['port']['id'])
                        body = self._router_interface_action(
                            'add', r['router']['id'], None, p3['port']['id'],
                            expected_code=exc.HTTPBadRequest.code)
                        self._assert_body_port_id_and_update_port(
                            body, update_port, p3['port']['id'],
                            r['router']['id'])

    def test_router_add_interface_overlapped_cidr_returns_400(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s1, self.subnet(
                    cidr='10.0.2.0/24') as s2:
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s1['subnet']['id'],
                                              None)
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s2['subnet']['id'],
                                              None)

                def try_overlapped_cidr(cidr):
                    with self.subnet(cidr=cidr) as s3:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s3['subnet']['id'],
                                                      None,
                                                      expected_code=exc.
                                                      HTTPBadRequest.code)
                # another subnet with same cidr
                try_overlapped_cidr('10.0.1.0/24')
                try_overlapped_cidr('10.0.2.0/24')
                # another subnet with overlapped cidr including s1
                try_overlapped_cidr('10.0.0.0/16')
                # another subnet with overlapped cidr including s2
                try_overlapped_cidr('10.0.2.128/28')

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

    def test_router_add_interface_cidr_overlapped_with_gateway(self):
        with self.router() as r, self.network() as ext_net:
            with self.subnet(cidr='10.0.1.0/24') as s1, self.subnet(
                    network=ext_net, cidr='10.0.0.0/16') as s2:
                ext_net_id = ext_net['network']['id']
                self._set_net_external(ext_net_id)
                self._add_external_gateway_to_router(
                    r['router']['id'], ext_net_id)
                res = self._router_interface_action(
                    'add', r['router']['id'], s1['subnet']['id'], None,
                    expected_code=exc.HTTPBadRequest.code)
                expected_msg = ("Bad router request: Cidr 10.0.1.0/24 of "
                                "subnet %(internal_subnet_id)s overlaps with "
                                "cidr 10.0.0.0/16 of subnet "
                                "%(external_subnet_id)s.") % {
                                    "external_subnet_id": s2['subnet']['id'],
                                    "internal_subnet_id": s1['subnet']['id']}
                self.assertEqual(expected_msg, res['NeutronError']['message'])

                # External network have multiple subnets.
                with self.subnet(network=ext_net,
                                 cidr='192.168.1.0/24') as s3, \
                        self.subnet(cidr='192.168.1.0/24') as s4:
                    res = self._router_interface_action(
                        'add', r['router']['id'], s4['subnet']['id'], None,
                        expected_code=exc.HTTPBadRequest.code)
                    expected_msg = (
                        "Bad router request: Cidr 192.168.1.0/24 of subnet "
                        "%(internal_subnet_id)s overlaps with cidr "
                        "192.168.1.0/24 of subnet %(external_subnet_id)s.") % {
                            "external_subnet_id": s3['subnet']['id'],
                            "internal_subnet_id": s4['subnet']['id']}
                    self.assertEqual(expected_msg,
                                     res['NeutronError']['message'])

    def test_router_set_gateway_cidr_overlapped_with_subnets(self):
        with self.router() as r, self.network() as ext_net:
            with self.subnet(network=ext_net, cidr='10.0.1.0/24') as s1, \
                    self.subnet(network=ext_net, cidr='10.0.2.0/24') as s2, \
                    self.subnet(cidr='10.0.2.0/24') as s3:
                ext_net_id = ext_net['network']['id']
                self._set_net_external(ext_net_id)
                self._router_interface_action(
                    'add', r['router']['id'],
                    s3['subnet']['id'], None)
                res = self._add_external_gateway_to_router(
                    r['router']['id'], ext_net_id,
                    ext_ips=[{'subnet_id': s1['subnet']['id']}],
                    expected_code=exc.HTTPBadRequest.code)
                expected_msg = (
                    "Bad router request: Cidr 10.0.2.0/24 of subnet "
                    "%(external_subnet_id)s overlaps with cidr 10.0.2.0/24 of "
                    "subnet %(internal_subnet_id)s.") % {
                        "external_subnet_id": s2["subnet"]["id"],
                        "internal_subnet_id": s3["subnet"]["id"]}
                self.assertEqual(expected_msg, res['NeutronError']['message'])

    def test_router_add_interface_by_port_cidr_overlapped_with_gateway(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s1, self.subnet(
                    cidr='10.0.0.0/16') as s2:
                with self.port(subnet=s1) as p:
                    self._set_net_external(s2['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])

                    res = self._router_interface_action(
                        'add', r['router']['id'], None, p['port']['id'],
                        expected_code=exc.HTTPBadRequest.code)
                    expected_msg = (
                        "Bad router request: Cidr 10.0.1.0/24 of subnet "
                        "%(internal_subnet_id)s overlaps with cidr "
                        "10.0.0.0/16 of subnet %(external_subnet_id)s.") % {
                            "external_subnet_id": s2['subnet']['id'],
                            "internal_subnet_id": s1['subnet']['id']}
                    self.assertEqual(expected_msg,
                                     res['NeutronError']['message'])

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
                    ip_version=lib_constants.IP_VERSION_6,
                    ipv6_ra_mode=lib_constants.IPV6_SLAAC,
                    ipv6_address_mode=lib_constants.IPV6_SLAAC)) as s3, (
                 self.subnet(
                    cidr='2001:db8:1::/64', network=n,
                    ip_version=lib_constants.IP_VERSION_6,
                    ipv6_ra_mode=lib_constants.DHCPV6_STATEFUL,
                    ipv6_address_mode=lib_constants.DHCPV6_STATEFUL)) as s4, (
                 self.subnet(
                    cidr='2001:db8:2::/64', network=n,
                    ip_version=lib_constants.IP_VERSION_6,
                    ipv6_ra_mode=lib_constants.DHCPV6_STATELESS,
                    ipv6_address_mode=lib_constants.DHCPV6_STATELESS)) as s5:
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

    def test_create_router_port_with_device_id_of_other_tenants_router(self):
        with self.router() as admin_router:
            with self.network(tenant_id='tenant_a',
                              set_context=True) as n:
                with self.subnet(network=n):
                    for device_owner in lib_constants.ROUTER_INTERFACE_OWNERS:
                        self._create_port(
                            self.fmt, n['network']['id'],
                            tenant_id='tenant_a',
                            device_id=admin_router['router']['id'],
                            device_owner=device_owner,
                            set_context=True,
                            expected_res_status=exc.HTTPConflict.code)

    def test_create_non_router_port_device_id_of_other_tenants_router_update(
            self):
        # This tests that HTTPConflict is raised if we create a non-router
        # port that matches the device_id of another tenants router and then
        # we change the device_owner to be network:router_interface.
        with self.router() as admin_router:
            with self.network(tenant_id='tenant_a',
                              set_context=True) as n:
                with self.subnet(network=n):
                    for device_owner in lib_constants.ROUTER_INTERFACE_OWNERS:
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

    def test_router_add_gateway_no_subnet_forbidden(self):
        with self.router() as r:
            with self.network() as n:
                self._set_net_external(n['network']['id'])
                with mock.patch.object(registry, 'publish') as notify:
                    errors = [
                        exceptions.NotificationError(
                            'foo_callback_id',
                            n_exc.InvalidInput(error_message='forbidden')),
                    ]

                    def failing_publish(resource, event, trigger, payload):
                        if (resource == resources.ROUTER_GATEWAY and
                                event == events.BEFORE_CREATE):
                            raise exceptions.CallbackFailure(
                                errors=errors)
                        return mock.DEFAULT
                    notify.side_effect = failing_publish
                    self._add_external_gateway_to_router(
                        r['router']['id'], n['network']['id'],
                        expected_code=exc.HTTPBadRequest.code)
                    notify.assert_any_call(
                        resources.ROUTER_GATEWAY,
                        events.BEFORE_CREATE,
                        mock.ANY, payload=mock.ANY)
                    # Find the call and look at the payload
                    calls = [call for call in notify.mock_calls
                        if call[1][0] == resources.ROUTER_GATEWAY and
                        call[1][1] == events.BEFORE_CREATE]
                    self.assertEqual(1, len(calls))
                    payload = calls[0][2]['payload']
                    self.assertEqual(r['router']['id'], payload.resource_id)
                    self.assertEqual(n['network']['id'],
                                     payload.metadata.get('network_id'))
                    self.assertEqual([], payload.metadata.get('subnets'))

    def test_router_add_gateway_notifications(self):
        with self.router() as r:
            with self.network() as n:
                with self.subnet(network=n) as s:
                    self._set_net_external(n['network']['id'])
                    with mock.patch.object(registry, 'publish') as notify:
                        res = self._add_external_gateway_to_router(
                            r['router']['id'], n['network']['id'],
                            ext_ips=[{'subnet_id': s['subnet']['id'],
                                      'ip_address': '10.0.0.4'}])
                        gw_info = res['router']['external_gateway_info']
                        ext_ips = gw_info['external_fixed_ips'][0]
                        expected_gw_ips = [ext_ips['ip_address']]
                        expected = [mock.call(
                                        resources.ROUTER_GATEWAY,
                                        events.AFTER_CREATE, mock.ANY,
                                        payload=mock.ANY)]
                        notify.assert_has_calls(expected)
                        # Find the call and look at the payload
                        calls = [call for call in notify.mock_calls
                            if call[1][0] == resources.ROUTER_GATEWAY and
                            call[1][1] == events.AFTER_CREATE]
                        self.assertEqual(1, len(calls))
                        payload = calls[0][2]['payload']
                        self.assertEqual(r['router']['id'],
                                         payload.resource_id)
                        self.assertEqual(n['network']['id'],
                                         payload.metadata.get('network_id'))
                        self.assertEqual(expected_gw_ips,
                                         payload.metadata.get('gateway_ips'))

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
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s['subnet']['id'],
                                          None)

            # we fail the first time, but not the second, when
            # the clean-up takes place
            notify.side_effect = [
                exceptions.CallbackFailure(errors=errors), None
            ]
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

            self._set_net_external(s['subnet']['network_id'])
            self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
            notify.side_effect = exceptions.CallbackFailure(errors=errors)
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
                    # remove properly to clean-up
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
            with self.subnet() as s:
                with self.port(subnet=s) as p:
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
            with (self.subnet(network=n, cidr='fd00::1/64',
                              ip_version=lib_constants.IP_VERSION_6)
                  ) as s1, self.subnet(network=n, cidr='fd01::1/64',
                                       ip_version=lib_constants.IP_VERSION_6
                                       ) as s2:
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
        self.assertEqual(404, res.status_int)

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
                self.assertEqual(exc.HTTPCreated.code, res.status_int)
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
                             {'network': {extnet_apidef.EXTERNAL: False}},
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
                                 {'network': {extnet_apidef.EXTERNAL: False}})

    def test_floatingip_crd_ops(self):
        with self.floatingip_with_assoc() as fip:
            self._validate_floating_ip(fip)

        # post-delete, check that it is really gone
        body = self._list('floatingips')
        self.assertEqual(0, len(body['floatingips']))

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
                        self.assertEqual(400, res.status_int)
                    for p in self._list('ports')['ports']:
                        if (p['device_owner'] ==
                                lib_constants.DEVICE_OWNER_FLOATINGIP):
                            self.fail('garbage port is not deleted')

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin._check_and_get_fip_assoc')

    def test_create_floatingip_with_assoc(
            self, expected_status=lib_constants.FLOATINGIP_STATUS_ACTIVE):
        with self.floatingip_with_assoc() as fip:
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertEqual(body['floatingip']['id'],
                             fip['floatingip']['id'])
            self.assertEqual(body['floatingip']['port_id'],
                             fip['floatingip']['port_id'])
            self.assertEqual(expected_status, body['floatingip']['status'])
            self.assertIsNotNone(body['floatingip']['fixed_ip_address'])
            self.assertIsNotNone(body['floatingip']['router_id'])

    def test_create_floatingip_non_admin_context_agent_notification(self):
        plugin = directory.get_plugin(plugin_constants.L3)
        if not hasattr(plugin, 'l3_rpc_notifier'):
            self.skipTest("Plugin does not support l3_rpc_notifier")

        with self.subnet(cidr='11.0.0.0/24') as public_sub,\
                self.port() as private_port,\
                self.router() as r:
            self._set_net_external(public_sub['subnet']['network_id'])
            subnet_id = private_port['port']['fixed_ips'][0]['subnet_id']
            private_sub = {'subnet': {'id': subnet_id}}

            self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'])
            self._router_interface_action(
                'add', r['router']['id'],
                private_sub['subnet']['id'], None)

            with mock.patch.object(plugin.l3_rpc_notifier,
                                   'routers_updated') as agent_notification:
                self._make_floatingip(
                    self.fmt,
                    public_sub['subnet']['network_id'],
                    port_id=private_port['port']['id'],
                    set_context=False)
                self.assertTrue(agent_notification.called)

    def test_floating_port_status_not_applicable(self):
        with self.floatingip_with_assoc():
            port_body = self._list('ports',
               query_params='device_owner=network:floatingip')['ports'][0]
            self.assertEqual(lib_constants.PORT_STATUS_NOTAPPLICABLE,
                             port_body['status'])

    def test_floatingip_update(
            self, expected_status=lib_constants.FLOATINGIP_STATUS_ACTIVE):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['fixed_ip_address'])
                self.assertEqual(expected_status, body['floatingip']['status'])

                port_id = p['port']['id']
                ip_address = p['port']['fixed_ips'][0]['ip_address']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEqual(port_id, body['floatingip']['port_id'])
                self.assertEqual(ip_address,
                                 body['floatingip']['fixed_ip_address'])

    def test_floatingip_update_subnet_gateway_disabled(
            self, expected_status=lib_constants.FLOATINGIP_STATUS_ACTIVE):
        """Attach a floating IP to an instance

        Verify that the floating IP can be associated to a port whose subnet's
        gateway ip is not connected to the external router, but the router
        has an ip in that subnet.
        """
        with self.subnet(cidr='30.0.0.0/24', gateway_ip=None) as private_sub:
            with self.port(private_sub) as p:
                subnet_id = p['port']['fixed_ips'][0]['subnet_id']
                private_sub = {'subnet': {'id': subnet_id}}
                port_id = p['port']['id']
                with self.router() as r:
                    self._router_interface_action('add', r['router']['id'],
                                                  None, port_id)
                with self.subnet(cidr='12.0.0.0/24') as public_sub:
                    self._set_net_external(public_sub['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                         r['router']['id'], public_sub['subnet']['network_id'])
                    fip = self._make_floatingip(self.fmt,
                                 public_sub['subnet']['network_id'])
                    body = self._show('floatingips', fip['floatingip']['id'])
                    self.assertEqual(expected_status,
                                     body['floatingip']['status'])
                    body = self._update('floatingips', fip['floatingip']['id'],
                                  {'floatingip': {'port_id': port_id}})
                    self.assertEqual(port_id, body['floatingip']['port_id'])
                    self.assertEqual(p['port']['fixed_ips'][0]['ip_address'],
                                     body['floatingip']['fixed_ip_address'])
                    self.assertEqual(r['router']['id'],
                                     body['floatingip']['router_id'])

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

    def test_floatingip_update_invalid_fixed_ip(self):
        with self.subnet() as s:
            with self.port(subnet=s) as p:
                with self.floatingip_with_assoc(
                        port_id=p['port']['id']) as fip:
                    self._update(
                        'floatingips', fip['floatingip']['id'],
                        {'floatingip': {'port_id': p['port']['id'],
                                        'fixed_ip_address': '2001:db8::a'}},
                        expected_code=exc.HTTPBadRequest.code)

    def test_floatingip_update_to_same_port_id_twice(
            self, expected_status=lib_constants.FLOATINGIP_STATUS_ACTIVE):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['fixed_ip_address'])
                self.assertEqual(expected_status, body['floatingip']['status'])

                port_id = p['port']['id']
                ip_address = p['port']['fixed_ips'][0]['ip_address']
                # 1. Update floating IP with port_id (associate)
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEqual(port_id, body['floatingip']['port_id'])
                self.assertEqual(ip_address,
                                 body['floatingip']['fixed_ip_address'])

                # 2. Update floating IP with same port again
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                # No errors, and nothing changed
                self.assertEqual(port_id, body['floatingip']['port_id'])
                self.assertEqual(ip_address,
                                 body['floatingip']['fixed_ip_address'])

    def test_floatingip_update_same_fixed_ip_same_port(self):
        with self.subnet() as private_sub:
            ip_range = list(netaddr.IPNetwork(private_sub['subnet']['cidr']))
            fixed_ip = [{'ip_address': str(ip_range[-3])}]
            with self.port(subnet=private_sub, fixed_ips=fixed_ip) as p:
                with self.router() as r:
                    with self.subnet(cidr='11.0.0.0/24') as public_sub:
                        self._set_net_external(
                            public_sub['subnet']['network_id'])
                        self._add_external_gateway_to_router(
                            r['router']['id'],
                            public_sub['subnet']['network_id'])
                        self._router_interface_action(
                            'add', r['router']['id'],
                            private_sub['subnet']['id'], None)
                        fip1 = self._make_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'])
                        fip2 = self._make_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'])
                        # 1. Update floating IP 1 with port_id and fixed_ip
                        body_1 = self._update(
                            'floatingips', fip1['floatingip']['id'],
                            {'floatingip': {'port_id': p['port']['id'],
                                        'fixed_ip_address': str(ip_range[-3])}
                             })
                        self.assertEqual(str(ip_range[-3]),
                            body_1['floatingip']['fixed_ip_address'])
                        self.assertEqual(p['port']['id'],
                            body_1['floatingip']['port_id'])
                        # 2. Update floating IP 2 with port_id and fixed_ip
                        # mock out the sequential check
                        plugin = 'neutron.db.l3_db.L3_NAT_dbonly_mixin'
                        check_get = mock.patch(
                            plugin + '._check_and_get_fip_assoc',
                            fip=fip2, floating_db=mock.ANY,
                            return_value=(p['port']['id'], str(ip_range[-3]),
                                          r['router']['id']))
                        check_and_get = check_get.start()
                        # do regular _check_and_get_fip_assoc() after skip
                        check_and_get.side_effect = check_get.stop()
                        self._update(
                            'floatingips', fip2['floatingip']['id'],
                            {'floatingip':
                                {'port_id': p['port']['id'],
                                 'fixed_ip_address': str(ip_range[-3])
                                 }}, exc.HTTPConflict.code)
                        body = self._show('floatingips',
                                          fip2['floatingip']['id'])
                        self.assertIsNone(
                            body['floatingip']['fixed_ip_address'])
                        self.assertIsNone(
                            body['floatingip']['port_id'])

    def test_create_multiple_floatingips_same_fixed_ip_same_port(self):
        '''This tests that if multiple API requests arrive to create
        floating IPs on same external network to same port with one
        fixed ip, the latter API requests would be blocked at
        database side.
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
                        # 1. Create floating IP 1
                        fip1 = self._make_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'],
                            p['port']['id'],
                            fixed_ip=str(ip_range[-3]))
                        # 2. Create floating IP 2
                        # mock out the sequential check
                        plugin = 'neutron.db.l3_db.L3_NAT_dbonly_mixin'
                        check_get = mock.patch(
                            plugin + '._check_and_get_fip_assoc',
                            fip=mock.ANY, floating_db=mock.ANY,
                            return_value=(p['port']['id'], str(ip_range[-3]),
                                          r['router']['id']))
                        check_and_get = check_get.start()
                        # do regular _check_and_get_fip_assoc() after skip
                        check_and_get.side_effect = check_get.stop()
                        self._make_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'],
                            p['port']['id'],
                            fixed_ip=str(ip_range[-3]),
                            http_status=exc.HTTPConflict.code)
                        # Test that floating IP 1 is successfully created
                        body = self._show('floatingips',
                                          fip1['floatingip']['id'])
                        self.assertEqual(
                            body['floatingip']['port_id'],
                            fip1['floatingip']['port_id'])

                    self._delete('ports', p['port']['id'])
                    # Test that port has been successfully deleted.
                    body = self._show('ports', p['port']['id'],
                                      expected_code=exc.HTTPNotFound.code)

    def test_first_floatingip_associate_notification(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                port_id = p['port']['id']
                ip_address = p['port']['fixed_ips'][0]['ip_address']
                with mock.patch.object(registry, 'notify') as notify:
                    body = self._update('floatingips',
                                        fip['floatingip']['id'],
                                        {'floatingip': {'port_id': port_id}})
                    fip_addr = fip['floatingip']['floating_ip_address']
                    fip_network_id = fip['floatingip']['floating_network_id']
                    fip_id = fip['floatingip']['id']
                    router_id = body['floatingip']['router_id']
                    body = self._show('routers', router_id)
                    notify.assert_any_call(resources.FLOATING_IP,
                                           events.AFTER_UPDATE,
                                           mock.ANY,
                                           context=mock.ANY,
                                           fixed_ip_address=ip_address,
                                           fixed_port_id=port_id,
                                           floating_ip_address=fip_addr,
                                           floating_network_id=fip_network_id,
                                           last_known_router_id=None,
                                           floating_ip_id=fip_id,
                                           router_id=router_id,
                                           association_event=True)

    def test_floatingip_disassociate_notification(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                port_id = p['port']['id']
                body = self._update('floatingips',
                                    fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                with mock.patch.object(registry, 'notify') as notify:
                    fip_addr = fip['floatingip']['floating_ip_address']
                    fip_network_id = fip['floatingip']['floating_network_id']
                    fip_id = fip['floatingip']['id']
                    router_id = body['floatingip']['router_id']
                    self._update('floatingips',
                                 fip['floatingip']['id'],
                                 {'floatingip': {'port_id': None}})
                    notify.assert_any_call(resources.FLOATING_IP,
                                           events.AFTER_UPDATE,
                                           mock.ANY,
                                           context=mock.ANY,
                                           fixed_ip_address=None,
                                           fixed_port_id=None,
                                           floating_ip_address=fip_addr,
                                           floating_network_id=fip_network_id,
                                           last_known_router_id=router_id,
                                           floating_ip_id=fip_id,
                                           router_id=None,
                                           association_event=False)

    def test_floatingip_association_on_unowned_router(self):
        # create a router owned by one tenant and associate the FIP with a
        # different tenant, assert that the FIP association succeeds
        with self.subnet(cidr='11.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router(tenant_id='router-owner',
                                 set_context=True) as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}

                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action(
                        'add', r['router']['id'],
                        private_sub['subnet']['id'], None)

                    self._make_floatingip(self.fmt,
                                          public_sub['subnet']['network_id'],
                                          port_id=private_port['port']['id'],
                                          fixed_ip=None,
                                          set_context=True)

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
                            self.assertEqual(port_id,
                                             body['floatingip']['port_id'])
                            self.assertEqual(
                                ip_address,
                                body['floatingip']['fixed_ip_address'])
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

    def test_floatingip_update_different_port_owner_as_admin(self):
        with self.subnet() as private_sub:
            with self.floatingip_no_assoc(private_sub) as fip:
                with self.port(subnet=private_sub, tenant_id='other') as p:
                    body = self._update('floatingips', fip['floatingip']['id'],
                                        {'floatingip':
                                         {'port_id': p['port']['id']}})
                    self.assertEqual(p['port']['id'],
                                     body['floatingip']['port_id'])

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
            self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_floating_ip_direct_port_delete_returns_409(self):
        found = False
        with self.floatingip_with_assoc():
            for p in self._list('ports')['ports']:
                if p['device_owner'] == lib_constants.DEVICE_OWNER_FLOATINGIP:
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
                    createport.return_value = {'fixed_ips': [], 'id': '44'}
                    res = self._create_floatingip(
                        self.fmt, public_sub['subnet']['network_id'],
                        port_id=p['port']['id'])
                    self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(
            'neutron.db.db_base_plugin_v2.NeutronDbPluginV2')

    def test_create_floatingip_with_subnet_id_non_admin(self):
        with self.subnet() as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.router():
                res = self._create_floatingip(
                    self.fmt,
                    public_sub['subnet']['network_id'],
                    subnet_id=public_sub['subnet']['id'],
                    set_context=True)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)

    def test_create_floatingip_with_subnet_id_and_fip_address(self):
        with self.network() as ext_net:
            self._set_net_external(ext_net['network']['id'])
            with self.subnet(ext_net, cidr='10.10.10.0/24') as ext_subnet:
                with self.router():
                    res = self._create_floatingip(
                        self.fmt,
                        ext_net['network']['id'],
                        subnet_id=ext_subnet['subnet']['id'],
                        floating_ip='10.10.10.100')
                    fip = self.deserialize(self.fmt, res)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        self.assertEqual('10.10.10.100',
                         fip['floatingip']['floating_ip_address'])

    def test_create_floatingip_with_subnet_and_invalid_fip_address(self):
        with self.network() as ext_net:
            self._set_net_external(ext_net['network']['id'])
            with self.subnet(ext_net, cidr='10.10.10.0/24') as ext_subnet:
                with self.router():
                    res = self._create_floatingip(
                        self.fmt,
                        ext_net['network']['id'],
                        subnet_id=ext_subnet['subnet']['id'],
                        floating_ip='20.20.20.200')
                    data = self.deserialize(self.fmt, res)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)
        msg = str(n_exc.InvalidIpForSubnet(ip_address='20.20.20.200'))
        self.assertEqual('InvalidIpForSubnet', data['NeutronError']['type'])
        self.assertEqual(msg, data['NeutronError']['message'])

    def test_create_floatingip_with_multisubnet_id(self):
        with self.network() as network:
            self._set_net_external(network['network']['id'])
            with self.subnet(network, cidr='10.0.12.0/24') as subnet1:
                with self.subnet(network, cidr='10.0.13.0/24') as subnet2:
                    with self.router():
                        res = self._create_floatingip(
                            self.fmt,
                            subnet1['subnet']['network_id'],
                            subnet_id=subnet1['subnet']['id'])
                        fip1 = self.deserialize(self.fmt, res)
                        res = self._create_floatingip(
                            self.fmt,
                            subnet1['subnet']['network_id'],
                            subnet_id=subnet2['subnet']['id'])
                        fip2 = self.deserialize(self.fmt, res)
        self.assertTrue(
            fip1['floatingip']['floating_ip_address'].startswith('10.0.12'))
        self.assertTrue(
            fip2['floatingip']['floating_ip_address'].startswith('10.0.13'))

    def test_create_floatingip_with_wrong_subnet_id(self):
        with self.network() as network1:
            self._set_net_external(network1['network']['id'])
            with self.subnet(network1, cidr='10.0.12.0/24') as subnet1:
                with self.network() as network2:
                    self._set_net_external(network2['network']['id'])
                    with self.subnet(network2, cidr='10.0.13.0/24') as subnet2:
                        with self.router():
                            res = self._create_floatingip(
                                self.fmt,
                                subnet1['subnet']['network_id'],
                                subnet_id=subnet2['subnet']['id'])
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

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
                    self.assertEqual(exc.HTTPNotFound.code, res.status_int)

    def test_create_floating_non_ext_network_returns_400(self):
        with self.subnet() as public_sub:
            # normally we would set the network of public_sub to be
            # external, but the point of this test is to handle when
            # that is not the case
            with self.router():
                res = self._create_floatingip(
                    self.fmt,
                    public_sub['subnet']['network_id'])
                self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

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
                    self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_create_floatingip_invalid_floating_network_id_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip(self.fmt, 'iamnotanuuid',
                                      uuidutils.generate_uuid(), '192.168.0.1')
        self.assertEqual(400, res.status_int)

    def test_create_floatingip_invalid_floating_port_id_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip(self.fmt, uuidutils.generate_uuid(),
                                      'iamnotanuuid', '192.168.0.1')
        self.assertEqual(400, res.status_int)

    def test_create_floatingip_invalid_fixed_ip_address_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip(self.fmt, uuidutils.generate_uuid(),
                                      uuidutils.generate_uuid(), 'iamnotnanip')
        self.assertEqual(400, res.status_int)

    def test_create_floatingip_invalid_fixed_ipv6_address_returns_400(self):
        # API-level test - no need to create all objects for l3 plugin
        res = self._create_floatingip(self.fmt, uuidutils.generate_uuid(),
                                      uuidutils.generate_uuid(), '2001:db8::a')
        self.assertEqual(400, res.status_int)

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
            self.assertEqual(1, len(res['floatingips']))
            res = self._list('floatingips', query_params="port_id=aaa")
            self.assertEqual(0, len(res['floatingips']))

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
                                                private_port['port']['id'])
                    fp2 = self._make_floatingip(self.fmt, network_ex_id2,
                                                private_port['port']['id'])
                    self.assertEqual(fp1['floatingip']['router_id'],
                                     r1['router']['id'])
                    self.assertEqual(fp2['floatingip']['router_id'],
                                     r2['router']['id'])

    def test_floatingip_same_external_and_internal(self):
        # Select router with subnet's gateway_ip for floatingip when
        # routers connected to same subnet and external network.
        with self.subnet(cidr="10.0.0.0/24") as exs,\
                self.subnet(cidr="12.0.0.0/24", gateway_ip="12.0.0.50") as ins:
            network_ex_id = exs['subnet']['network_id']
            self._set_net_external(network_ex_id)

            r2i_fixed_ips = [{'ip_address': '12.0.0.2'}]
            with self.router() as r1,\
                    self.router() as r2,\
                    self.port(subnet=ins,
                              fixed_ips=r2i_fixed_ips) as r2i_port:
                self._add_external_gateway_to_router(
                    r1['router']['id'],
                    network_ex_id)
                self._router_interface_action('add', r2['router']['id'],
                                              None,
                                              r2i_port['port']['id'])
                self._router_interface_action('add', r1['router']['id'],
                                              ins['subnet']['id'],
                                              None)
                self._add_external_gateway_to_router(
                    r2['router']['id'],
                    network_ex_id)

                with self.port(subnet=ins,
                               fixed_ips=[{'ip_address': '12.0.0.8'}]
                               ) as private_port:

                    fp = self._make_floatingip(self.fmt, network_ex_id,
                                               private_port['port']['id'])
                    self.assertEqual(r1['router']['id'],
                                     fp['floatingip']['router_id'])

    def _test_floatingip_via_router_interface(self, http_status):
        # NOTE(yamamoto): "exs" subnet is just to provide a gateway port
        # for the router.  Otherwise the test would fail earlier without
        # reaching the code we want to test. (bug 1556884)
        with self.subnet(cidr="10.0.0.0/24") as exs, \
                self.subnet(cidr="10.0.1.0/24") as ins1, \
                self.subnet(cidr="10.0.2.0/24") as ins2:
            network_ex_id = exs['subnet']['network_id']
            self._set_net_external(network_ex_id)
            network_in2_id = ins2['subnet']['network_id']
            self._set_net_external(network_in2_id)
            with self.router() as r1, self.port(subnet=ins1) as private_port:
                self._add_external_gateway_to_router(r1['router']['id'],
                                                     network_ex_id)
                self._router_interface_action('add', r1['router']['id'],
                                              ins1['subnet']['id'], None)
                self._router_interface_action('add', r1['router']['id'],
                                              ins2['subnet']['id'], None)
                self._make_floatingip(self.fmt,
                                      network_id=network_in2_id,
                                      port_id=private_port['port']['id'],
                                      http_status=http_status)

    def _get_router_for_floatingip_without_device_owner_check(
            self, context, internal_port,
            internal_subnet, external_network_id):
        gw_port = orm.aliased(models_v2.Port, name="gw_port")
        routerport_qry = context.session.query(
            l3_models.RouterPort.router_id,
            models_v2.IPAllocation.ip_address
        ).join(
            l3_models.RouterPort.port, models_v2.Port.fixed_ips
        ).filter(
            models_v2.Port.network_id == internal_port['network_id'],
            l3_models.RouterPort.port_type.in_(
                lib_constants.ROUTER_INTERFACE_OWNERS
            ),
            models_v2.IPAllocation.subnet_id == internal_subnet['id']
        ).join(
            gw_port, gw_port.device_id == l3_models.RouterPort.router_id
        ).filter(
            gw_port.network_id == external_network_id,
        ).distinct()

        first_router_id = None
        for router_id, interface_ip in routerport_qry:
            if interface_ip == internal_subnet['gateway_ip']:
                return router_id
            if not first_router_id:
                first_router_id = router_id
        if first_router_id:
            return first_router_id

        raise l3_exc.ExternalGatewayForFloatingIPNotFound(
            subnet_id=internal_subnet['id'],
            external_network_id=external_network_id,
            port_id=internal_port['id'])

    def test_floatingip_via_router_interface_returns_404(self):
        self._test_floatingip_via_router_interface(exc.HTTPNotFound.code)

    def test_floatingip_via_router_interface_returns_201(self):
        # Override get_router_for_floatingip, as
        # networking-midonet's L3 service plugin would do.
        plugin = directory.get_plugin(plugin_constants.L3)
        with mock.patch.object(plugin, "get_router_for_floatingip",
                self._get_router_for_floatingip_without_device_owner_check):
            self._test_floatingip_via_router_interface(exc.HTTPCreated.code)

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        found = False
        with self.floatingip_with_assoc():
            for p in self._list('ports')['ports']:
                if p['device_owner'] == lib_constants.DEVICE_OWNER_ROUTER_INTF:
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
                if p['device_owner'] == lib_constants.DEVICE_OWNER_ROUTER_INTF:
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
                           ip_version=lib_constants.IP_VERSION_6,
                           ipv6_ra_mode=mode,
                           ipv6_address_mode=mode)

    def test_router_delete_subnet_inuse_returns_409(self):
        with self.router() as r:
            with self.subnet() as s:
                self._test_router_delete_subnet_inuse_returns_409(r, s)

    def test_router_delete_ipv6_slaac_subnet_inuse_returns_409(self):
        with self.router() as r:
            with self._ipv6_subnet(lib_constants.IPV6_SLAAC) as s:
                self._test_router_delete_subnet_inuse_returns_409(r, s)

    def test_router_delete_dhcpv6_stateless_subnet_inuse_returns_409(self):
        with self.router() as r:
            with self._ipv6_subnet(lib_constants.DHCPV6_STATELESS) as s:
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
            self.assertEqual('10.0.0.10',
                             fp['floatingip']['floating_ip_address'])

    def test_create_floatingip_with_specific_ip_out_of_allocation(self):
        with self.subnet(cidr='10.0.0.0/24',
                         allocation_pools=[
                             {'start': '10.0.0.10', 'end': '10.0.0.20'}]
                         ) as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fp = self._make_floatingip(self.fmt, network_id,
                                       floating_ip='10.0.0.30')
            self.assertEqual('10.0.0.30',
                             fp['floatingip']['floating_ip_address'])

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

    def test_create_floatingips_native_quotas(self):
        quota = 1
        cfg.CONF.set_override('quota_floatingip', quota, group='QUOTAS')
        with self.subnet() as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._create_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'],
                subnet_id=public_sub['subnet']['id'])
            self.assertEqual(exc.HTTPCreated.code, res.status_int)
            res = self._create_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'],
                subnet_id=public_sub['subnet']['id'])
            self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_router_specify_id_backend(self):
        plugin = directory.get_plugin(plugin_constants.L3)
        router_req = {'router': {'id': _uuid(), 'name': 'router',
                                 'tenant_id': 'foo',
                                 'admin_state_up': True}}
        result = plugin.create_router(context.Context('', 'foo'), router_req)
        self.assertEqual(router_req['router']['id'], result['id'])

    def test_create_floatingip_ipv6_only_network_returns_400(self):
        with self.subnet(cidr="2001:db8::/48",
                         ip_version=lib_constants.IP_VERSION_6) as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._create_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'])
            self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4(self):
        with self.network() as n,\
                self.subnet(cidr="2001:db8::/48",
                            ip_version=lib_constants.IP_VERSION_6, network=n),\
                self.subnet(cidr="192.168.1.0/24",
                            ip_version=lib_constants.IP_VERSION_4, network=n):
            self._set_net_external(n['network']['id'])
            fip = self._make_floatingip(self.fmt, n['network']['id'])
            fip_set = netaddr.IPSet(netaddr.IPNetwork("192.168.1.0/24"))
            fip_ip = fip['floatingip']['floating_ip_address']
            self.assertIn(netaddr.IPAddress(fip_ip), fip_set)

    def test_create_floatingip_with_assoc_to_ipv6_subnet(self):
        with self.subnet() as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.subnet(cidr="2001:db8::/48",
                             ip_version=lib_constants.IP_VERSION_6
                             ) as private_sub:
                with self.port(subnet=private_sub) as private_port:
                    res = self._create_floatingip(
                        self.fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_create_floatingip_with_assoc_to_ipv4_and_ipv6_port(self):
        with self.network() as n,\
                self.subnet(cidr='10.0.0.0/24', network=n) as s4,\
                self.subnet(cidr='2001:db8::/64',
                            ip_version=lib_constants.IP_VERSION_6, network=n),\
                self.port(subnet=s4) as p:
            self.assertEqual(2, len(p['port']['fixed_ips']))
            ipv4_address = next(i['ip_address'] for i in
                    p['port']['fixed_ips'] if
                    netaddr.IPAddress(i['ip_address']).version == 4)
            with self.floatingip_with_assoc(port_id=p['port']['id']) as fip:
                self.assertEqual(fip['floatingip']['fixed_ip_address'],
                                 ipv4_address)
                floating_ip = netaddr.IPAddress(
                        fip['floatingip']['floating_ip_address'])
                self.assertEqual(4, floating_ip.version)

    def test_create_router_gateway_fails_nested(self):
        # Force _update_router_gw_info failure
        plugin = directory.get_plugin(plugin_constants.L3)
        if not isinstance(plugin, l3_db.L3_NAT_dbonly_mixin):
            self.skipTest("Plugin is not L3_NAT_dbonly_mixin")
        ctx = context.Context('', 'foo')
        data = {'router': {
            'name': 'router1', 'admin_state_up': True,
            'external_gateway_info': {'network_id': 'some_uuid'},
            'tenant_id': 'some_tenant'}}

        def mock_fail__update_router_gw_info(ctx, router_id, info,
                                             router=None):
            # Fail with breaking transaction
            with ctx.session.begin(subtransactions=True):
                raise n_exc.NeutronException

        mock.patch.object(plugin, '_update_router_gw_info',
                          side_effect=mock_fail__update_router_gw_info).start()

        def create_router_with_transaction(ctx, data):
            # Emulates what many plugins do
            with ctx.session.begin(subtransactions=True):
                plugin.create_router(ctx, data)

        # Verify router doesn't persist on failure
        self.assertRaises(n_exc.NeutronException,
                          create_router_with_transaction, ctx, data)
        routers = plugin.get_routers(ctx)
        self.assertEqual(0, len(routers))

    def test_create_router_gateway_fails_nested_delete_router_failed(self):
        # Force _update_router_gw_info failure
        plugin = directory.get_plugin(plugin_constants.L3)
        if not isinstance(plugin, l3_db.L3_NAT_dbonly_mixin):
            self.skipTest("Plugin is not L3_NAT_dbonly_mixin")
        ctx = context.Context('', 'foo')
        data = {'router': {
            'name': 'router1', 'admin_state_up': True,
            'external_gateway_info': {'network_id': 'some_uuid'},
            'tenant_id': 'some_tenant'}}

        def mock_fail__update_router_gw_info(ctx, router_id, info,
                                             router=None):
            # Fail with breaking transaction
            with ctx.session.begin(subtransactions=True):
                raise n_exc.NeutronException

        def mock_fail_delete_router(ctx, router_id):
            with ctx.session.begin(subtransactions=True):
                raise Exception()

        mock.patch.object(plugin, '_update_router_gw_info',
                          side_effect=mock_fail__update_router_gw_info).start()
        mock.patch.object(plugin, 'delete_router',
                          mock_fail_delete_router).start()

        def create_router_with_transaction(ctx, data):
            # Emulates what many plugins do
            with ctx.session.begin(subtransactions=True):
                plugin.create_router(ctx, data)

        # Verify router doesn't persist on failure
        self.assertRaises(n_exc.NeutronException,
                          create_router_with_transaction, ctx, data)
        routers = plugin.get_routers(ctx)
        self.assertEqual(0, len(routers))

    def test_router_add_interface_by_port_fails_nested(self):
        # Force _validate_router_port_info failure
        plugin = directory.get_plugin(plugin_constants.L3)
        if not isinstance(plugin, l3_db.L3_NAT_dbonly_mixin):
            self.skipTest("Plugin is not L3_NAT_dbonly_mixin")
        orig_update_port = self.plugin.update_port

        def mock_fail__validate_router_port_info(ctx, router, port_id):
            # Fail with raising BadRequest exception
            msg = "Failure mocking..."
            raise n_exc.BadRequest(resource='router', msg=msg)

        def mock_update_port_with_transaction(ctx, id, port):
            # Update port within a sub-transaction
            with ctx.session.begin(subtransactions=True):
                orig_update_port(ctx, id, port)

        def add_router_interface_with_transaction(ctx, router_id,
                                                  interface_info):
            # Call add_router_interface() within a sub-transaction
            with ctx.session.begin():
                plugin.add_router_interface(ctx, router_id, interface_info)

        tenant_id = _uuid()
        ctx = context.Context('', tenant_id)
        with self.network(tenant_id=tenant_id) as network, (
             self.router(name='router1', admin_state_up=True,
                         tenant_id=tenant_id)) as router:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             tenant_id=tenant_id) as subnet:
                fixed_ips = [{'subnet_id': subnet['subnet']['id']}]
                with self.port(subnet=subnet, fixed_ips=fixed_ips,
                               tenant_id=tenant_id) as port:
                    mock.patch.object(
                        self.plugin, 'update_port',
                        side_effect=(
                            mock_update_port_with_transaction)).start()
                    mock.patch.object(
                        plugin, '_validate_router_port_info',
                        side_effect=(
                            mock_fail__validate_router_port_info)).start()
                    self.assertRaises(n_exc.BadRequest,
                        add_router_interface_with_transaction,
                        ctx, router['router']['id'],
                        {'port_id': port['port']['id']})

                    # fetch port and confirm device_id and device_owner
                    body = self._show('ports', port['port']['id'])
                    self.assertEqual('', body['port']['device_owner'])
                    self.assertEqual('', body['port']['device_id'])

    def _test__notify_gateway_port_ip_changed_helper(self, gw_ip_change=True):
        plugin = directory.get_plugin(plugin_constants.L3)
        if not hasattr(plugin, 'l3_rpc_notifier'):
            self.skipTest("Plugin does not support l3_rpc_notifier")
        # make sure the callback is registered.
        registry.subscribe(
            l3_db.L3RpcNotifierMixin._notify_gateway_port_ip_changed,
            resources.PORT,
            events.AFTER_UPDATE)
        with mock.patch.object(plugin.l3_rpc_notifier,
                               'routers_updated') as chk_method:
            with self.router() as router:
                with self.subnet(cidr='1.1.1.0/24') as subnet:
                    self._set_net_external(subnet['subnet']['network_id'])
                    router_id = router['router']['id']
                    self._add_external_gateway_to_router(
                        router_id,
                        subnet['subnet']['network_id'])
                    body = self._show('routers', router_id)
                    gateway_ips = body['router']['external_gateway_info'][
                        'external_fixed_ips']
                    gateway_ip_len = len(gateway_ips)
                    self.assertEqual(1, gateway_ip_len)
                    gw_port_id = None
                    for p in self._list('ports')['ports']:
                        if (p['device_owner'] ==
                                lib_constants.DEVICE_OWNER_ROUTER_GW and
                                p['device_id'] == router_id):
                            gw_port_id = p['id']
                    self.assertIsNotNone(gw_port_id)
                    gw_ip_len = 1
                    if gw_ip_change:
                        gw_ip_len += 1
                        data = {'port': {'fixed_ips': [
                            {'ip_address': '1.1.1.101'},
                            {'ip_address': '1.1.1.100'}]}}
                    else:
                        gw_ip = gateway_ips[0]['ip_address']
                        data = {'port': {'fixed_ips': [
                            {'ip_address': gw_ip}]}}
                    req = self.new_update_request('ports', data,
                                                  gw_port_id)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(gw_ip_len, len(res['port']['fixed_ips']))

                    body = self._show('routers', router_id)
                    gateway_ip_len = len(
                        body['router']['external_gateway_info'][
                            'external_fixed_ips'])
                    self.assertEqual(gw_ip_len, gateway_ip_len)
                    chk_method.assert_called_with(mock.ANY,
                                                  [router_id], None)
                    self.assertEqual(gw_ip_len, chk_method.call_count)

    def test__notify_gateway_port_ip_changed(self):
        """Test to make sure notification to routers occurs when the gateway
            ip address changed.
        """
        self._test__notify_gateway_port_ip_changed_helper()

    def test__notify_gateway_port_ip_not_changed(self):
        """Test to make sure no notification to routers occurs when the gateway
            ip address is not changed.
        """
        self._test__notify_gateway_port_ip_changed_helper(gw_ip_change=False)

    def test_update_subnet_gateway_for_external_net(self):
        """Test to make sure notification to routers occurs when the gateway
            ip address of a subnet of the external network is changed.
        """
        plugin = directory.get_plugin(plugin_constants.L3)
        if not hasattr(plugin, 'l3_rpc_notifier'):
            self.skipTest("Plugin does not support l3_rpc_notifier")
        # make sure the callback is registered.
        registry.subscribe(
            l3_db.L3RpcNotifierMixin._notify_subnet_gateway_ip_update,
            resources.SUBNET,
            events.AFTER_UPDATE)
        with mock.patch.object(plugin.l3_rpc_notifier,
                               'routers_updated') as chk_method:
            with self.network() as network:
                allocation_pools = [{'start': '120.0.0.3',
                                     'end': '120.0.0.254'}]
                with self.subnet(network=network,
                                 gateway_ip='120.0.0.1',
                                 allocation_pools=allocation_pools,
                                 cidr='120.0.0.0/24') as subnet:
                    kwargs = {
                        'device_owner': lib_constants.DEVICE_OWNER_ROUTER_GW,
                        'device_id': 'fake_device'}
                    with self.port(subnet=subnet, **kwargs):
                        data = {'subnet': {'gateway_ip': '120.0.0.2'}}
                        req = self.new_update_request('subnets', data,
                                                      subnet['subnet']['id'])
                        res = self.deserialize(self.fmt,
                                               req.get_response(self.api))
                        self.assertEqual(data['subnet']['gateway_ip'],
                                         res['subnet']['gateway_ip'])
                        chk_method.assert_called_with(mock.ANY,
                                                      ['fake_device'], None)

    def test__notify_subnetpool_address_scope_update(self):
        plugin = directory.get_plugin(plugin_constants.L3)

        tenant_id = _uuid()
        with mock.patch.object(
            plugin, 'notify_routers_updated') as chk_method, \
                self.subnetpool(prefixes=['10.0.0.0/24'],
                                admin=True, name='sp',
                                tenant_id=tenant_id) as subnetpool, \
                self.router(tenant_id=tenant_id) as router, \
                self.network(tenant_id=tenant_id) as network:
            subnetpool_id = subnetpool['subnetpool']['id']
            data = {'subnet': {
                    'network_id': network['network']['id'],
                    'subnetpool_id': subnetpool_id,
                    'prefixlen': 24,
                    'ip_version': lib_constants.IP_VERSION_4,
                    'tenant_id': tenant_id}}
            req = self.new_create_request('subnets', data)
            subnet = self.deserialize(self.fmt, req.get_response(self.api))

            admin_ctx = context.get_admin_context()
            plugin.add_router_interface(
                admin_ctx,
                router['router']['id'], {'subnet_id': subnet['subnet']['id']})
            l3_db.L3RpcNotifierMixin._notify_subnetpool_address_scope_update(
                mock.ANY, mock.ANY, mock.ANY,
                payload=events.DBEventPayload(
                    admin_ctx, resource_id=subnetpool_id))
            chk_method.assert_called_with(admin_ctx, [router['router']['id']])

    def test_janitor_clears_orphaned_floatingip_port(self):
        plugin = directory.get_plugin(plugin_constants.L3)
        with self.network() as n:
            # floating IP ports are initially created with a device ID of
            # PENDING and are updated after the floating IP is actually
            # created.
            port_res = self._create_port(
                self.fmt, n['network']['id'],
                tenant_id=n['network']['tenant_id'], device_id='PENDING',
                device_owner=lib_constants.DEVICE_OWNER_FLOATINGIP)
            port = self.deserialize(self.fmt, port_res)
            plugin._clean_garbage()
            # first call should just have marked it as a candidate so port
            # should still exist
            port = self._show('ports', port['port']['id'])
            self.assertEqual('PENDING', port['port']['device_id'])
            # second call will delete the port since it has no associated
            # floating IP
            plugin._clean_garbage()
            self._show('ports', port['port']['id'],
                       expected_code=exc.HTTPNotFound.code)

    def test_janitor_updates_port_device_id(self):
        # if a server dies after the floating IP is created but before it
        # updates the floating IP port device ID, the janitor will be
        # responsible for updating the device ID to the correct value.
        plugin = directory.get_plugin(plugin_constants.L3)
        with self.floatingip_with_assoc() as fip:
            fip_port = self._list('ports',
                query_params='device_owner=network:floatingip')['ports'][0]
            # simulate a failed update by just setting the device_id of
            # the fip port back to PENDING
            data = {'port': {'device_id': 'PENDING'}}
            self._update('ports', fip_port['id'], data)
            plugin._clean_garbage()
            # first call just marks as candidate, so it shouldn't be changed
            port = self._show('ports', fip_port['id'])
            self.assertEqual('PENDING', port['port']['device_id'])
            # second call updates device ID to fip
            plugin._clean_garbage()
            # first call just marks as candidate, so it shouldn't be changed
            port = self._show('ports', fip_port['id'])
            self.assertEqual(fip['floatingip']['id'],
                             port['port']['device_id'])

    def test_janitor_doesnt_delete_if_fixed_in_interim(self):
        # here we ensure that the janitor doesn't delete the port on the second
        # call if the conditions have been fixed
        plugin = directory.get_plugin(plugin_constants.L3)
        with self.network() as n:
            port_res = self._create_port(
                self.fmt, n['network']['id'],
                tenant_id=n['network']['tenant_id'], device_id='PENDING',
                device_owner=lib_constants.DEVICE_OWNER_FLOATINGIP)
            port = self.deserialize(self.fmt, port_res)
            plugin._clean_garbage()
            # first call should just have marked it as a candidate so port
            # should still exist
            port = self._show('ports', port['port']['id'])
            self.assertEqual('PENDING', port['port']['device_id'])
            data = {'port': {'device_id': 'something_else'}}
            self._update('ports', port['port']['id'], data)
            # now that the device ID has changed, the janitor shouldn't delete
            plugin._clean_garbage()
            self._show('ports', port['port']['id'])

    def test_router_delete_callback(self):
        def prevent_router_deletion(*args, **kwargs):
            # unsubscribe now that we have invoked the callback
            registry.unsubscribe(prevent_router_deletion, resources.ROUTER,
                                 events.BEFORE_DELETE)
            raise exc.HTTPForbidden

        registry.subscribe(prevent_router_deletion, resources.ROUTER,
                           events.BEFORE_DELETE)

        with self.subnet():
            res = self._create_router(self.fmt, _uuid())
            router = self.deserialize(self.fmt, res)
            self._delete('routers', router['router']['id'],
                         exc.HTTPForbidden.code)

    def test_associate_to_dhcp_port_fails(self):
        with self.subnet(cidr="10.0.0.0/24",
                         ip_version=lib_constants.IP_VERSION_4) as sub:
            with self.port(subnet=sub,
                           device_owner=lib_constants.DEVICE_OWNER_DHCP) as p:
                res = self._create_floatingip(
                     self.fmt,
                     sub['subnet']['network_id'],
                     port_id=p['port']['id'])
                self.assertEqual(exc.HTTPBadRequest.code, res.status_int)


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
                interfaces = routers[0][lib_constants.INTERFACE_KEY]
                self.assertEqual(1, len(interfaces))
                subnets = interfaces[0]['subnets']
                self.assertEqual(1, len(subnets))
                subnet_id = subnets[0]['id']
                wanted_subnetid = p['port']['fixed_ips'][0]['subnet_id']
                self.assertEqual(wanted_subnetid, subnet_id)

    def test_l3_agent_sync_interfaces(self):
        """Test L3 interfaces query return valid result"""
        with self.router() as router1, self.router() as router2:
            with self.port() as port1, self.port() as port2:
                self._router_interface_action('add',
                                              router1['router']['id'],
                                              None,
                                              port1['port']['id'])
                self._router_interface_action('add',
                                              router2['router']['id'],
                                              None,
                                              port2['port']['id'])
                admin_ctx = context.get_admin_context()
                router1_id = router1['router']['id']
                router2_id = router2['router']['id']

                # Verify if router1 pass in, return only interface from router1
                ifaces = self.plugin._get_sync_interfaces(admin_ctx,
                                                          [router1_id])
                self.assertEqual(1, len(ifaces))
                self.assertEqual(router1_id,
                                 ifaces[0]['device_id'])

                # Verify if router1 and router2 pass in, return both interfaces
                ifaces = self.plugin._get_sync_interfaces(admin_ctx,
                                                          [router1_id,
                                                           router2_id])
                self.assertEqual(2, len(ifaces))
                device_list = [i['device_id'] for i in ifaces]
                self.assertIn(router1_id, device_list)
                self.assertIn(router2_id, device_list)

                # Verify if no router pass in, return empty list
                ifaces = self.plugin._get_sync_interfaces(admin_ctx, None)
                self.assertEqual(0, len(ifaces))

    def test_l3_agent_routers_query_ignore_interfaces_with_moreThanOneIp(self):
        with self.router() as r, self.subnet(
                cidr='9.0.1.0/24') as subnet, self.port(
                    subnet=subnet,
                    fixed_ips=[{'ip_address': '9.0.1.3'}]) as p1, self.port(
                        subnet=subnet,
                        fixed_ips=[{'ip_address': '9.0.1.100'},
                                   {'ip_address': '9.0.1.101'}]) as p2:
            # Cannot have multiple IPv4 subnets on router port,
            # see neutron.db.l3_db line L752-L754.
            self._router_interface_action(
                'add', r['router']['id'],
                None, p2['port']['id'],
                expected_code=exc.HTTPBadRequest.code)

            self._router_interface_action('add',
                                          r['router']['id'],
                                          None,
                                          p1['port']['id'])
            port = {'port': {'fixed_ips':
                             [{'ip_address': '9.0.1.4',
                               'subnet_id': subnet['subnet']['id']},
                              {'ip_address': '9.0.1.5',
                               'subnet_id': subnet['subnet']['id']}]}}
            ctx = context.get_admin_context()
            self.assertRaises(
                n_exc.BadRequest,
                self.core_plugin.update_port,
                ctx, p1['port']['id'], port)

            routers = self.plugin.get_sync_data(ctx, None)
            self.assertEqual(1, len(routers))
            interfaces = routers[0].get(lib_constants.INTERFACE_KEY,
                                        [])
            self.assertEqual(1, len(interfaces))
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          None,
                                          p1['port']['id'])

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
            floatingips = routers[0][lib_constants.FLOATINGIP_KEY]
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
            plugin = directory.get_plugin(plugin_constants.L3)
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

    def test_floatingips_create_precommit_event(self):
        fake_method = mock.Mock()
        try:
            registry.subscribe(fake_method, resources.FLOATING_IP,
                               events.PRECOMMIT_CREATE)
            with self.floatingip_with_assoc() as f:
                fake_method.assert_called_once_with(
                    resources.FLOATING_IP, events.PRECOMMIT_CREATE, mock.ANY,
                    context=mock.ANY, floatingip=mock.ANY,
                    floatingip_id=f['floatingip']['id'],
                    floatingip_db=mock.ANY)
        finally:
            registry.unsubscribe(fake_method, resources.FLOATING_IP,
                                 events.PRECOMMIT_CREATE)

    def test_floatingip_delete_after_event(self):
        fake_method = mock.Mock()
        try:
            registry.subscribe(fake_method, resources.FLOATING_IP,
                               events.AFTER_DELETE)
            with self.subnet(cidr='11.0.0.0/24') as public_sub:
                self._set_net_external(public_sub['subnet']['network_id'])
                f = self._make_floatingip(self.fmt,
                                          public_sub['subnet']['network_id'],
                                          port_id=None,
                                          fixed_ip=None,
                                          set_context=True)
                self._delete('floatingips', f['floatingip']['id'])
                fake_method.assert_called_once_with(
                    resources.FLOATING_IP, events.AFTER_DELETE, mock.ANY,
                    context=mock.ANY, description=mock.ANY,
                    dns_domain=mock.ANY, dns_name=mock.ANY,
                    fixed_ip_address=f['floatingip']['fixed_ip_address'],
                    floating_ip_address=f['floatingip']['floating_ip_address'],
                    floating_network_id=f['floatingip']['floating_network_id'],
                    id=f['floatingip']['id'],
                    port_id=f['floatingip']['port_id'],
                    project_id=f['floatingip']['project_id'],
                    router_id=f['floatingip']['router_id'],
                    status=f['floatingip']['status'],
                    tenant_id=f['floatingip']['tenant_id'])
        finally:
            registry.unsubscribe(fake_method, resources.FLOATING_IP,
                                 events.AFTER_DELETE)

    def test_router_create_precommit_event(self):
        nset = lambda *a, **k: setattr(k['router_db'], 'name', 'hello')
        registry.subscribe(nset, resources.ROUTER, events.PRECOMMIT_CREATE)
        with self.router() as r:
            self.assertEqual('hello', r['router']['name'])

    def test_router_create_event_exception_preserved(self):
        # this exception should be propagated out of the callback and
        # converted into its API equivalent of 404
        e404 = mock.Mock(side_effect=l3_exc.RouterNotFound(router_id='1'))
        registry.subscribe(e404, resources.ROUTER, events.PRECOMMIT_CREATE)
        res = self._create_router(self.fmt, 'tenid')
        self.assertEqual(exc.HTTPNotFound.code, res.status_int)
        # make sure nothing committed
        body = self._list('routers')
        self.assertFalse(body['routers'])

    def test_router_update_precommit_event(self):

        def _nset(r, v, s, payload=None):
            setattr(payload.desired_state, 'name',
                    payload.states[0]['name'] + '_ha!')

        registry.subscribe(_nset, resources.ROUTER, events.PRECOMMIT_UPDATE)
        with self.router(name='original') as r:
            update = self._update('routers', r['router']['id'],
                                  {'router': {'name': 'hi'}})
            # our rude callback should have changed the name to the original
            # plus some extra
            self.assertEqual('original_ha!', update['router']['name'])

    def test_router_update_event_exception_preserved(self):
        # this exception should be propagated out of the callback and
        # converted into its API equivalent of 404
        e404 = mock.Mock(side_effect=l3_exc.RouterNotFound(router_id='1'))
        registry.subscribe(e404, resources.ROUTER, events.PRECOMMIT_UPDATE)
        with self.router(name='a') as r:
            self._update('routers', r['router']['id'],
                         {'router': {'name': 'hi'}},
                         expected_code=exc.HTTPNotFound.code)
        # ensure it stopped the commit
        new = self._show('routers', r['router']['id'])
        self.assertEqual('a', new['router']['name'])

    def test_router_delete_precommit_event(self):
        deleted = []
        auditor = lambda *a, **k: deleted.append(k['router_id'])
        registry.subscribe(auditor, resources.ROUTER, events.PRECOMMIT_DELETE)
        with self.router() as r:
            self._delete('routers', r['router']['id'])
        self.assertEqual([r['router']['id']], deleted)

    def test_router_delete_event_exception_preserved(self):
        # this exception should be propagated out of the callback and
        # converted into its API equivalent of 409
        e409 = mock.Mock(side_effect=l3_exc.RouterInUse(router_id='1'))
        registry.subscribe(e409, resources.ROUTER, events.PRECOMMIT_DELETE)
        with self.router() as r:
            self._delete('routers', r['router']['id'],
                         expected_code=exc.HTTPConflict.code)
        # ensure it stopped the commit
        self.assertTrue(self._show('routers', r['router']['id']))


class L3BaseForIntTests(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=None, ext_mgr=None, service_plugins=None):
        if not plugin:
            plugin = 'neutron.tests.unit.extensions.test_l3.TestL3NatIntPlugin'
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        ext_mgr = ext_mgr or L3TestExtensionManager()

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
        super(L3NatDBIntAgentSchedulingTestCase, self).setUp(
            plugin, ext_mgr, service_plugins)
        self.adminContext = context.get_admin_context()

    def _assert_router_on_agent(self, router_id, agent_host):
        plugin = directory.get_plugin(plugin_constants.L3)
        agents = plugin.list_l3_agents_hosting_router(
            self.adminContext, router_id)['agents']
        self.assertEqual(1, len(agents))
        self.assertEqual(agents[0]['host'], agent_host)

    def test_router_update_gateway_scheduling_not_supported(self):
        plugin = directory.get_plugin(plugin_constants.L3)
        mock.patch.object(plugin, 'router_supports_scheduling',
                          return_value=False).start()
        with self.router() as r:
            with self.subnet() as s1:
                with self.subnet() as s2:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._set_net_external(s2['subnet']['network_id'])
                    # this should pass even though there are multiple
                    # external networks since no scheduling decision needs
                    # to be made
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])


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

    def test__ensure_host_set_on_port_bad_bindings(self):
        for b in (portbindings.VIF_TYPE_BINDING_FAILED,
                  portbindings.VIF_TYPE_UNBOUND):
            port = {'id': 'id', portbindings.HOST_ID: 'somehost',
                    portbindings.VIF_TYPE: b}
            self.l3_rpc_cb._ensure_host_set_on_port(None, 'somehost', port)
            self.assertTrue(self.l3_rpc_cb.plugin.update_port.called)

    def test__ensure_host_set_on_port_update_on_concurrent_delete(self):
        port_id = 'foo_port_id'
        port = {
            'id': port_id,
            'device_owner': DEVICE_OWNER_COMPUTE,
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
            mock.ANY, port_id, {'port': {portbindings.HOST_ID: mock.ANY}})
        self.assertTrue(mock_log.call_count)
        expected_message = ('Port foo_port_id not found while updating '
                            'agent binding for router foo_router_id.')
        actual_message = mock_log.call_args[0][0] % mock_log.call_args[0][1]
        self.assertEqual(expected_message, actual_message)

    def test__ensure_host_set_on_ports_dvr_ha_router_with_gatway(self):
        context = mock.Mock()
        host = "fake_host"
        router_id = 'foo_router_id'
        router = {"id": router_id,
                  "gw_port_host": host,
                  "gw_port": {"id": "foo_port_id"},
                  "distributed": True,
                  "ha": True}
        mock__ensure = mock.Mock()
        self.l3_rpc_cb._ensure_host_set_on_port = mock__ensure
        self.l3_rpc_cb._ensure_host_set_on_ports(context, host, [router])
        mock__ensure.assert_called_once_with(
            context, host, router["gw_port"], router_id, ha_router_port=True)


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


class TestL3DbOperationBounds(test_db_base_plugin_v2.DbOperationBoundMixin,
                              L3NatTestCaseMixin,
                              ml2_base.ML2TestFramework):
    def setUp(self):
        super(TestL3DbOperationBounds, self).setUp()
        ext_mgr = L3TestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.kwargs = self.get_api_kwargs()

    def test_router_list_queries_constant(self):
        with self.subnet(**self.kwargs) as s:
            self._set_net_external(s['subnet']['network_id'])

            def router_maker():
                ext_info = {'network_id': s['subnet']['network_id']}
                res = self._create_router(
                                    self.fmt,
                                    arg_list=('external_gateway_info',),
                                    external_gateway_info=ext_info,
                                    **self.kwargs)
                return self.deserialize(self.fmt, res)

            self._assert_object_list_queries_constant(router_maker, 'routers')


class TestL3DbOperationBoundsTenant(TestL3DbOperationBounds):
    admin = False


class L3NatDBTestCaseMixin(object):
    """L3_NAT_dbonly_mixin specific test cases."""

    def setUp(self):
        super(L3NatDBTestCaseMixin, self).setUp()
        plugin = directory.get_plugin(plugin_constants.L3)
        if not isinstance(plugin, l3_db.L3_NAT_dbonly_mixin):
            self.skipTest("Plugin is not L3_NAT_dbonly_mixin")

    def test_create_router_gateway_fails(self):
        """Force _update_router_gw_info failure and see
        the exception is propagated.
        """

        plugin = directory.get_plugin(plugin_constants.L3)
        ctx = context.Context('', 'foo')

        class MyException(Exception):
            pass

        mock.patch.object(plugin, '_update_router_gw_info',
                          side_effect=MyException).start()
        with self.network() as n:
            data = {'router': {
                'name': 'router1', 'admin_state_up': True,
                'tenant_id': ctx.tenant_id,
                'external_gateway_info': {'network_id': n['network']['id']}}}

            self.assertRaises(MyException, plugin.create_router, ctx, data)
            # Verify router doesn't persist on failure
            routers = plugin.get_routers(ctx)
            self.assertEqual(0, len(routers))


class L3NatDBIntTestCase(L3BaseForIntTests, L3NatTestCaseBase,
                         L3NatDBTestCaseMixin):

    """Unit tests for core plugin with L3 routing integrated."""
    pass


class L3NatDBSepTestCase(L3BaseForSepTests, L3NatTestCaseBase,
                         L3NatDBTestCaseMixin):

    """Unit tests for a separate L3 routing service plugin."""

    def test_port_deletion_prevention_handles_missing_port(self):
        pl = directory.get_plugin(plugin_constants.L3)
        self.assertIsNone(
            pl.prevent_l3_port_deletion(context.get_admin_context(), 'fakeid')
        )


class L3TestExtensionManagerWithDNS(L3TestExtensionManager):

    def get_resources(self):
        return l3.L3.get_resources()


class L3NatDBFloatingIpTestCaseWithDNS(L3BaseForSepTests, L3NatTestCaseMixin):
    """Unit tests for floating ip with external DNS integration"""

    fmt = 'json'
    DNS_NAME = 'test'
    DNS_DOMAIN = 'test-domain.org.'
    PUBLIC_CIDR = '11.0.0.0/24'
    PRIVATE_CIDR = '10.0.0.0/24'
    mock_client = mock.MagicMock()
    mock_admin_client = mock.MagicMock()
    MOCK_PATH = ('neutron.services.externaldns.drivers.'
                 'designate.driver.get_clients')
    mock_config = {'return_value': (mock_client, mock_admin_client)}
    _extension_drivers = ['dns']

    def setUp(self):
        ext_mgr = L3TestExtensionManagerWithDNS()
        plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(L3NatDBFloatingIpTestCaseWithDNS, self).setUp(plugin=plugin,
                                                            ext_mgr=ext_mgr)
        cfg.CONF.set_override('external_dns_driver', 'designate')
        self.mock_client.reset_mock()
        self.mock_admin_client.reset_mock()

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, set_context=False, tenant_id=None,
                        **kwargs):
        new_arg_list = ('dns_domain',)
        if arg_list is not None:
            new_arg_list = arg_list + new_arg_list
        return super(L3NatDBFloatingIpTestCaseWithDNS,
                     self)._create_network(fmt, name, admin_state_up,
                                           arg_list=new_arg_list,
                                           set_context=set_context,
                                           tenant_id=tenant_id,
                                           **kwargs)

    def _create_port(self, fmt, name, admin_state_up,
                     arg_list=None, set_context=False, tenant_id=None,
                     **kwargs):
        new_arg_list = ('dns_name',)
        if arg_list is not None:
            new_arg_list = arg_list + new_arg_list
        return super(L3NatDBFloatingIpTestCaseWithDNS,
                     self)._create_port(fmt, name, admin_state_up,
                                        arg_list=new_arg_list,
                                        set_context=set_context,
                                        tenant_id=tenant_id,
                                        **kwargs)

    def _create_net_sub_port(self, dns_domain='', dns_name=''):
        with self.network(dns_domain=dns_domain) as n:
            with self.subnet(cidr=self.PRIVATE_CIDR, network=n) as private_sub:
                with self.port(private_sub, dns_name=dns_name) as p:
                    return n, private_sub, p

    @contextlib.contextmanager
    def _create_floatingip_with_dns(self, net_dns_domain='', port_dns_name='',
                                    flip_dns_domain='', flip_dns_name='',
                                    assoc_port=False, private_sub=None):

        if private_sub is None:
            n, private_sub, p = self._create_net_sub_port(
                    dns_domain=net_dns_domain, dns_name=port_dns_name)

        data = {'fmt': self.fmt}
        data['dns_domain'] = flip_dns_domain
        data['dns_name'] = flip_dns_name

        # Set ourselves up to call the right function with
        # the right arguments for the with block
        if assoc_port:
            data['tenant_id'] = n['network']['tenant_id']
            data['port_id'] = p['port']['id']
            create_floatingip = self.floatingip_with_assoc
        else:
            data['private_sub'] = private_sub
            create_floatingip = self.floatingip_no_assoc

        with create_floatingip(**data) as flip:
            yield flip['floatingip']

    @contextlib.contextmanager
    def _create_floatingip_with_dns_on_update(self, net_dns_domain='',
            port_dns_name='', flip_dns_domain='', flip_dns_name=''):
        n, private_sub, p = self._create_net_sub_port(
            dns_domain=net_dns_domain, dns_name=port_dns_name)
        with self._create_floatingip_with_dns(flip_dns_domain=flip_dns_domain,
                flip_dns_name=flip_dns_name, private_sub=private_sub) as flip:
            flip_id = flip['id']
            data = {'floatingip': {'port_id': p['port']['id']}}
            req = self.new_update_request('floatingips', data, flip_id)
            res = req.get_response(self._api_for_resource('floatingip'))
            self.assertEqual(200, res.status_code)

            floatingip = self.deserialize(self.fmt, res)['floatingip']
            self.assertEqual(p['port']['id'], floatingip['port_id'])

            yield flip

    def _get_in_addr_zone_name(self, in_addr_name):
        units = self._get_bytes_or_nybles_to_skip(in_addr_name)
        return '.'.join(in_addr_name.split('.')[int(units):])

    def _get_bytes_or_nybles_to_skip(self, in_addr_name):
        if 'in-addr.arpa' in in_addr_name:
            return ((
                32 - cfg.CONF.designate.ipv4_ptr_zone_prefix_size) / 8)
        return (128 - cfg.CONF.designate.ipv6_ptr_zone_prefix_size) / 4

    def _get_in_addr(self, record):
        in_addr_name = netaddr.IPAddress(record).reverse_dns
        in_addr_zone_name = self._get_in_addr_zone_name(in_addr_name)
        return in_addr_name, in_addr_zone_name

    def _assert_recordset_created(self, floating_ip_address):
        # The recordsets.create function should be called with:
        # dns_domain, dns_name, 'A', ip_address ('A' for IPv4, 'AAAA' for IPv6)
        self.mock_client.recordsets.create.assert_called_with(self.DNS_DOMAIN,
            self.DNS_NAME, 'A', [floating_ip_address])
        in_addr_name, in_addr_zone_name = self._get_in_addr(
            floating_ip_address)
        self.mock_admin_client.recordsets.create.assert_called_with(
            in_addr_zone_name, in_addr_name, 'PTR',
            ['%s.%s' % (self.DNS_NAME, self.DNS_DOMAIN)])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create(self, mock_args):
        with self._create_floatingip_with_dns():
            pass
        self.mock_client.recordsets.create.assert_not_called()
        self.mock_admin_client.recordsets.create.assert_not_called()

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_flip_dns(self, mock_args):
        with self._create_floatingip_with_dns(flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_net_port_dns(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain=self.DNS_DOMAIN,
                port_dns_name=self.DNS_NAME, assoc_port=True) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_flip_and_net_port_dns(self, mock_args):
        # If both network+port and the floating ip have dns domain and
        # dns name, floating ip's information should take priority
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain='junkdomain.org.',
                port_dns_name='junk', flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME, assoc_port=True) as flip:
            floatingip = flip
        # External DNS service should have been called with floating ip's
        # dns information, not the network+port's dns information
        self._assert_recordset_created(floatingip['floating_ip_address'])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port(self, mock_args):
        with self._create_floatingip_with_dns_on_update():
            pass
        self.mock_client.recordsets.create.assert_not_called()
        self.mock_admin_client.recordsets.create.assert_not_called()

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_flip_dns(self, mock_args):
        with self._create_floatingip_with_dns_on_update(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_net_port_dns(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns_on_update(
                net_dns_domain=self.DNS_DOMAIN,
                port_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_flip_and_net_port_dns(self,
                                                                  mock_args):
        # If both network+port and the floating ip have dns domain and
        # dns name, floating ip's information should take priority
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns_on_update(
                net_dns_domain='junkdomain.org.',
                port_dns_name='junk',
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_disassociate_port(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain=self.DNS_DOMAIN,
                port_dns_name=self.DNS_NAME, assoc_port=True) as flip:
            fake_recordset = {'id': '',
                    'records': [flip['floating_ip_address']]}
            # This method is called during recordset deletion, which
            # will fail unless the list function call returns something like
            # this fake value
            self.mock_client.recordsets.list.return_value = ([fake_recordset])
            # Port gets disassociated if port_id is not in the request body
            data = {'floatingip': {}}
            req = self.new_update_request('floatingips', data, flip['id'])
            res = req.get_response(self._api_for_resource('floatingip'))
        floatingip = self.deserialize(self.fmt, res)['floatingip']
        flip_port_id = floatingip['port_id']
        self.assertEqual(200, res.status_code)
        self.assertIsNone(flip_port_id)
        in_addr_name, in_addr_zone_name = self._get_in_addr(
            floatingip['floating_ip_address'])
        self.mock_client.recordsets.delete.assert_called_with(
            self.DNS_DOMAIN, '')
        self.mock_admin_client.recordsets.delete.assert_called_with(
            in_addr_zone_name, in_addr_name)

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_delete(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
            # This method is called during recordset deletion, which will
            # fail unless the list function call returns something like
            # this fake value
            fake_recordset = {'id': '',
                              'records': [floatingip['floating_ip_address']]}
            self.mock_client.recordsets.list.return_value = [fake_recordset]
        in_addr_name, in_addr_zone_name = self._get_in_addr(
                floatingip['floating_ip_address'])
        self.mock_client.recordsets.delete.assert_called_with(
                self.DNS_DOMAIN, '')
        self.mock_admin_client.recordsets.delete.assert_called_with(
                in_addr_zone_name, in_addr_name)

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_no_PTR_record(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)

        # Disabling this option should stop the admin client from creating
        # PTR records. So set this option and make sure the admin client
        # wasn't called to create any records
        cfg.CONF.set_override('allow_reverse_dns_lookup', False,
                              group='designate')

        with self._create_floatingip_with_dns(flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip

        self.mock_client.recordsets.create.assert_called_with(self.DNS_DOMAIN,
                self.DNS_NAME, 'A', [floatingip['floating_ip_address']])
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])


class L3DBFloatingIpTestCaseLogging(L3BaseForSepTests, L3NatTestCaseMixin):

    def setUp(self, *args, **kwargs):
        ext_mgr = L3TestExtensionManagerWithDNS()
        plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        super(L3DBFloatingIpTestCaseLogging, self).setUp(plugin=plugin,
                                                         ext_mgr=ext_mgr)
        self.mock_log = mock.patch.object(l3_db, 'LOG').start()

    def test_create_floatingip_event_logging_port_assoc(self):
        with self.floatingip_with_assoc() as fip:
            msg_vars = {'fip_id': fip['floatingip']['id'],
                        'ext_ip': fip['floatingip']['floating_ip_address'],
                        'port_id': fip['floatingip']['port_id'],
                        'assoc': 'associated'}
            self.mock_log.info.assert_called_once_with(l3_db.FIP_ASSOC_MSG,
                                                       msg_vars)

    def test_update_floatingip_event_logging(self):
        with self.port() as port:
            private_subnet = {'subnet': {
                'id': port['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_subnet) as fip:
                self.mock_log.info.assert_not_called()
                fip_id = fip['floatingip']['id']
                data = {'floatingip': {'port_id': port['port']['id']}}
                req = self.new_update_request('floatingips', data, fip_id)
                res = req.get_response(self._api_for_resource('floatingip'))
                self.assertEqual(200, res.status_code)
                msg_vars = {'fip_id': fip['floatingip']['id'],
                            'ext_ip': fip['floatingip']['floating_ip_address'],
                            'port_id': port['port']['id'],
                            'assoc': 'associated'}
                self.mock_log.info.assert_called_once_with(l3_db.FIP_ASSOC_MSG,
                                                           msg_vars)

    def test_update_floatingip_event_logging_disassociate(self):
        with self.floatingip_with_assoc() as fip:
            self.mock_log.reset_mock()
            fip_id = fip['floatingip']['id']
            data = {'floatingip': {'port_id': None}}
            req = self.new_update_request('floatingips', data, fip_id)
            res = req.get_response(self._api_for_resource('floatingip'))
            self.assertEqual(200, res.status_code)
            msg_vars = {'fip_id': fip['floatingip']['id'],
                        'ext_ip': fip['floatingip']['floating_ip_address'],
                        'port_id': fip['floatingip']['port_id'],
                        'assoc': 'disassociated'}
            self.mock_log.info.assert_called_once_with(l3_db.FIP_ASSOC_MSG,
                                                       msg_vars)
