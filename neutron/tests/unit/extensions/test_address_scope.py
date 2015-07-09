# Copyright (c) 2015 Red Hat, Inc.
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

import webob.exc

from neutron.api.v2 import attributes as attr
from neutron import context
from neutron.db import address_scope_db
from neutron.db import db_base_plugin_v2
from neutron.extensions import address_scope as ext_address_scope
from neutron.tests.unit.db import test_db_base_plugin_v2

DB_PLUGIN_KLASS = ('neutron.tests.unit.extensions.test_address_scope.'
                   'AddressScopeTestPlugin')


class AddressScopeTestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attr.RESOURCE_ATTRIBUTE_MAP.update(
            ext_address_scope.RESOURCE_ATTRIBUTE_MAP)
        return ext_address_scope.Address_scope.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class AddressScopeTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def _create_address_scope(self, fmt, expected_res_status=None,
                              admin=False, **kwargs):
        address_scope = {'address_scope': {}}
        for k, v in kwargs.items():
            address_scope['address_scope'][k] = str(v)

        address_scope_req = self.new_create_request('address-scopes',
                                                    address_scope, fmt)

        if not admin:
            neutron_context = context.Context('', kwargs.get('tenant_id',
                                                             self._tenant_id))
            address_scope_req.environ['neutron.context'] = neutron_context

        address_scope_res = address_scope_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(address_scope_res.status_int, expected_res_status)
        return address_scope_res

    def _make_address_scope(self, fmt, admin=False, **kwargs):
        res = self._create_address_scope(fmt, admin=admin, **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    @contextlib.contextmanager
    def address_scope(self, admin=False, **kwargs):
        addr_scope = self._make_address_scope(self.fmt, admin, **kwargs)
        yield addr_scope

    def _test_create_address_scope(self, admin=False, expected=None, **kwargs):
        keys = kwargs.copy()
        keys.setdefault('tenant_id', self._tenant_id)
        with self.address_scope(admin=admin, **keys) as addr_scope:
            self._validate_resource(addr_scope, keys, 'address_scope')
            if expected:
                self._compare_resource(addr_scope, expected, 'address_scope')
        return addr_scope

    def _test_update_address_scope(self, addr_scope_id, data, admin=False,
                                   expected=None, tenant_id=None):
        update_req = self.new_update_request(
            'address-scopes', data, addr_scope_id)
        if not admin:
            neutron_context = context.Context('', tenant_id or self._tenant_id)
            update_req.environ['neutron.context'] = neutron_context

        update_res = update_req.get_response(self.ext_api)
        if expected:
            addr_scope = self.deserialize(self.fmt, update_res)
            self._compare_resource(addr_scope, expected, 'address_scope')
            return addr_scope

        return update_res


class AddressScopeTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                             address_scope_db.AddressScopeDbMixin):
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["address-scope"]


class TestAddressScope(AddressScopeTestCase):

    def setUp(self):
        plugin = DB_PLUGIN_KLASS
        ext_mgr = AddressScopeTestExtensionManager()
        super(TestAddressScope, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def test_create_address_scope(self):
        expected_addr_scope = {'name': 'foo-address-scope',
                               'tenant_id': self._tenant_id,
                               'shared': False}
        self._test_create_address_scope(name='foo-address-scope',
                                        expected=expected_addr_scope)

    def test_create_address_scope_empty_name(self):
        expected_addr_scope = {'name': '',
                               'tenant_id': self._tenant_id,
                               'shared': False}
        self._test_create_address_scope(name='', expected=expected_addr_scope)

        # no name specified
        self._test_create_address_scope(expected=expected_addr_scope)

    def test_create_address_scope_shared_admin(self):
        expected_addr_scope = {'name': 'foo-address-scope', 'shared': True}
        self._test_create_address_scope(name='foo-address-scope', admin=True,
                                        shared=True,
                                        expected=expected_addr_scope)

    def test_created_address_scope_shared_non_admin(self):
        res = self._create_address_scope(self.fmt, name='foo-address-scope',
                                         tenant_id=self._tenant_id,
                                         admin=False, shared=True)
        self.assertEqual(webob.exc.HTTPForbidden.code, res.status_int)

    def test_created_address_scope_specify_id(self):
        res = self._create_address_scope(self.fmt, name='foo-address-scope',
                                         id='foo-id')
        self.assertEqual(webob.exc.HTTPClientError.code, res.status_int)

    def test_delete_address_scope(self):
        with self.address_scope(name='foo-address-scope') as addr_scope:
            self._delete('address-scopes', addr_scope['address_scope']['id'])
            self._show('address-scopes', addr_scope['address_scope']['id'],
                       expected_code=webob.exc.HTTPNotFound.code)

    def test_update_address_scope(self):
        addr_scope = self._test_create_address_scope(name='foo-address-scope')
        data = {'address_scope': {'name': 'bar-address-scope'}}
        self._test_update_address_scope(addr_scope['address_scope']['id'],
                                        data, expected=data['address_scope'])

    def test_update_address_scope_shared_true_admin(self):
        addr_scope = self._test_create_address_scope(name='foo-address-scope')
        data = {'address_scope': {'shared': True}}
        self._test_update_address_scope(addr_scope['address_scope']['id'],
                                        data, admin=True,
                                        expected=data['address_scope'])

    def test_update_address_scope_shared_true_non_admin(self):
        addr_scope = self._test_create_address_scope(name='foo-address-scope')
        data = {'address_scope': {'shared': True}}
        res = self._test_update_address_scope(
            addr_scope['address_scope']['id'], data, admin=False)
        self.assertEqual(webob.exc.HTTPForbidden.code, res.status_int)

    def test_update_address_scope_shared_false_admin(self):
        addr_scope = self._test_create_address_scope(name='foo-address-scope',
                                                     admin=True, shared=True)
        data = {'address_scope': {'shared': False}}
        res = self._test_update_address_scope(
            addr_scope['address_scope']['id'], data, admin=True)
        self.assertEqual(webob.exc.HTTPClientError.code, res.status_int)

    def test_get_address_scope(self):
        addr_scope = self._test_create_address_scope(name='foo-address-scope')
        req = self.new_show_request('address-scopes',
                                    addr_scope['address_scope']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(addr_scope['address_scope']['id'],
                         res['address_scope']['id'])

    def test_get_address_scope_different_tenants_not_shared(self):
        addr_scope = self._test_create_address_scope(name='foo-address-scope')
        req = self.new_show_request('address-scopes',
                                    addr_scope['address_scope']['id'])
        neutron_context = context.Context('', 'not-the-owner')
        req.environ['neutron.context'] = neutron_context
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_get_address_scope_different_tenants_shared(self):
        addr_scope = self._test_create_address_scope(name='foo-address-scope',
                                                     shared=True, admin=True)
        req = self.new_show_request('address-scopes',
                                    addr_scope['address_scope']['id'])
        neutron_context = context.Context('', 'test-tenant-2')
        req.environ['neutron.context'] = neutron_context
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(addr_scope['address_scope']['id'],
                         res['address_scope']['id'])

    def test_list_address_scopes(self):
        self._test_create_address_scope(name='foo-address-scope')
        self._test_create_address_scope(name='bar-address-scope')
        res = self._list('address-scopes')
        self.assertEqual(2, len(res['address_scopes']))

    def test_list_address_scopes_different_tenants_shared(self):
        self._test_create_address_scope(name='foo-address-scope', shared=True,
                                        admin=True)
        admin_res = self._list('address-scopes')
        mortal_res = self._list(
            'address-scopes',
            neutron_context=context.Context('', 'not-the-owner'))
        self.assertEqual(1, len(admin_res['address_scopes']))
        self.assertEqual(1, len(mortal_res['address_scopes']))

    def test_list_address_scopes_different_tenants_not_shared(self):
        self._test_create_address_scope(name='foo-address-scope')
        admin_res = self._list('address-scopes')
        mortal_res = self._list(
            'address-scopes',
            neutron_context=context.Context('', 'not-the-owner'))
        self.assertEqual(1, len(admin_res['address_scopes']))
        self.assertEqual(0, len(mortal_res['address_scopes']))
