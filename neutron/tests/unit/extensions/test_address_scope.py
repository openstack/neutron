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
from unittest import mock

import netaddr
from neutron_lib.api.definitions import address_scope as apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins import directory
import webob.exc

from neutron.db import address_scope_db
from neutron.db import db_base_plugin_v2
from neutron.extensions import address_scope as ext_address_scope
from neutron.tests.common import test_db_base_plugin_v2

DB_PLUGIN_KLASS = ('neutron.tests.unit.extensions.test_address_scope.'
                   'AddressScopeTestPlugin')


class AddressScopeTestExtensionManager:

    def get_resources(self):
        return ext_address_scope.Address_scope.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class AddressScopeTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def _create_address_scope(self, fmt, ip_version=constants.IP_VERSION_4,
                              expected_res_status=None, admin=False,
                              tenant_id=None, **kwargs):
        address_scope = {'address_scope': {}}
        address_scope['address_scope']['ip_version'] = ip_version
        tenant_id = tenant_id or self._tenant_id
        for k, v in kwargs.items():
            address_scope['address_scope'][k] = str(v)

        address_scope_req = self.new_create_request('address-scopes',
                                                    address_scope, fmt,
                                                    tenant_id=tenant_id,
                                                    as_admin=admin)

        address_scope_res = address_scope_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, address_scope_res.status_int)
        return address_scope_res

    def _make_address_scope(self, fmt, ip_version, admin=False, tenant_id=None,
                            **kwargs):
        res = self._create_address_scope(fmt, ip_version,
                                         admin=admin, tenant_id=tenant_id,
                                         **kwargs)
        self._check_http_response(res)
        return self.deserialize(fmt, res)

    @contextlib.contextmanager
    def address_scope(self, ip_version=constants.IP_VERSION_4,
                      admin=False, tenant_id=None, **kwargs):
        tenant_id = tenant_id if tenant_id else kwargs.pop(
            'tenant_id', None)
        addr_scope = self._make_address_scope(self.fmt, ip_version,
                                              admin, tenant_id, **kwargs)
        yield addr_scope

    def _test_create_address_scope(self, ip_version=constants.IP_VERSION_4,
                                   admin=False, expected=None, **kwargs):
        keys = kwargs.copy()
        keys.setdefault('tenant_id', self._tenant_id)
        with self.address_scope(ip_version,
                                admin=admin, **keys) as addr_scope:
            keys['ip_version'] = ip_version
            self._validate_resource(addr_scope, keys, 'address_scope')
            if expected:
                self._compare_resource(addr_scope, expected, 'address_scope')
        return addr_scope

    def _test_update_address_scope(self, addr_scope_id, data, admin=False,
                                   expected=None, tenant_id=None):
        update_req = self.new_update_request(
            'address-scopes', data, addr_scope_id,
            tenant_id=tenant_id or self._tenant_id,
            as_admin=admin)

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

    supported_extension_aliases = [apidef.ALIAS]


class TestAddressScope(AddressScopeTestCase):

    def setUp(self):
        plugin = DB_PLUGIN_KLASS
        ext_mgr = AddressScopeTestExtensionManager()
        super().setUp(plugin=plugin, ext_mgr=ext_mgr)

    def test_create_address_scope_ipv4(self):
        expected_addr_scope = {'name': 'foo-address-scope',
                               'tenant_id': self._tenant_id,
                               'shared': False,
                               'ip_version': constants.IP_VERSION_4}
        self._test_create_address_scope(name='foo-address-scope',
                                        expected=expected_addr_scope)

    def test_create_address_scope_ipv6(self):
        expected_addr_scope = {'name': 'foo-address-scope',
                               'tenant_id': self._tenant_id,
                               'shared': False,
                               'ip_version': constants.IP_VERSION_6}
        self._test_create_address_scope(constants.IP_VERSION_6,
                                        name='foo-address-scope',
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
        self._test_create_address_scope(constants.IP_VERSION_6,
                                        name='bar-address-scope')
        res = self._list('address-scopes')
        self.assertEqual(2, len(res['address_scopes']))

    def test_list_address_scopes_different_tenants_shared(self):
        self._test_create_address_scope(name='foo-address-scope', shared=True,
                                        admin=True)
        admin_res = self._list('address-scopes')
        mortal_res = self._list(
            'address-scopes', tenant_id='not-the-owner')
        self.assertEqual(1, len(admin_res['address_scopes']))
        self.assertEqual(1, len(mortal_res['address_scopes']))

    def test_list_address_scopes_different_tenants_not_shared(self):
        self._test_create_address_scope(constants.IP_VERSION_6,
                                        name='foo-address-scope')
        admin_res = self._list('address-scopes')
        mortal_res = self._list(
            'address-scopes', tenant_id='not-the-owner')
        self.assertEqual(1, len(admin_res['address_scopes']))
        self.assertEqual(0, len(mortal_res['address_scopes']))


class TestSubnetPoolsWithAddressScopes(AddressScopeTestCase):
    def setUp(self):
        plugin = DB_PLUGIN_KLASS
        ext_mgr = AddressScopeTestExtensionManager()
        super().setUp(plugin=plugin,
                      ext_mgr=ext_mgr)

    def _test_create_subnetpool(self, prefixes, expected=None,
                                admin=False, **kwargs):
        keys = kwargs.copy()
        keys.setdefault('tenant_id', self._tenant_id)
        with self.subnetpool(prefixes, admin, **keys) as subnetpool:
            self._validate_resource(subnetpool, keys, 'subnetpool')
            if expected:
                self._compare_resource(subnetpool, expected, 'subnetpool')
        return subnetpool

    def test_create_subnetpool_associate_address_scope(self):
        with self.address_scope(name='foo-address-scope') as addr_scope:
            address_scope_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            expected = {'address_scope_id': address_scope_id}
            self._test_create_subnetpool([subnet.cidr], expected=expected,
                                         name='foo-subnetpool',
                                         min_prefixlen='21',
                                         address_scope_id=address_scope_id)

    def test_create_subnetpool_associate_invalid_address_scope(self):
        self.assertRaises(
            webob.exc.HTTPClientError, self._test_create_subnetpool, [],
            min_prefixlen='21', address_scope_id='foo-addr-scope-id')

    def test_create_subnetpool_assoc_address_scope_with_prefix_intersect(self):
        with self.address_scope(name='foo-address-scope') as addr_scope:
            address_scope_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            expected = {'address_scope_id': address_scope_id}
            self._test_create_subnetpool([subnet.cidr], expected=expected,
                                         name='foo-subnetpool',
                                         min_prefixlen='21',
                                         address_scope_id=address_scope_id)
            overlap_subnet = netaddr.IPNetwork('10.10.10.10/24')
            self.assertRaises(
                webob.exc.HTTPClientError, self._test_create_subnetpool,
                [overlap_subnet.cidr], min_prefixlen='21',
                address_scope_id=address_scope_id)

    def test_update_subnetpool_associate_address_scope(self):
        subnet = netaddr.IPNetwork('10.10.10.0/24')
        initial_subnetpool = self._test_create_subnetpool([subnet.cidr],
                                                          name='foo-sp',
                                                          min_prefixlen='21')
        with self.address_scope(name='foo-address-scope') as addr_scope:
            address_scope_id = addr_scope['address_scope']['id']
            data = {'subnetpool': {'address_scope_id': address_scope_id}}
            req = self.new_update_request(
                'subnetpools', data, initial_subnetpool['subnetpool']['id'])
            api = self._api_for_resource('subnetpools')
            res = self.deserialize(self.fmt, req.get_response(api))
            self._compare_resource(res, data['subnetpool'], 'subnetpool')

    def test_update_subnetpool_associate_invalid_address_scope(self):
        subnet = netaddr.IPNetwork('10.10.10.0/24')
        initial_subnetpool = self._test_create_subnetpool([subnet.cidr],
                                                          name='foo-sp',
                                                          min_prefixlen='21')
        data = {'subnetpool': {'address_scope_id': 'foo-addr-scope-id'}}
        req = self.new_update_request(
            'subnetpools', data, initial_subnetpool['subnetpool']['id'])
        api = self._api_for_resource('subnetpools')
        res = req.get_response(api)
        self.assertEqual(webob.exc.HTTPClientError.code, res.status_int)

    def test_update_subnetpool_disassociate_address_scope(self):
        with self.address_scope(name='foo-address-scope') as addr_scope:
            address_scope_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            expected = {'address_scope_id': address_scope_id}
            initial_subnetpool = self._test_create_subnetpool(
                [subnet.cidr], expected=expected, name='foo-sp',
                min_prefixlen='21', address_scope_id=address_scope_id)

            data = {'subnetpool': {'address_scope_id': None}}
            req = self.new_update_request(
                'subnetpools', data, initial_subnetpool['subnetpool']['id'])
            api = self._api_for_resource('subnetpools')
            res = self.deserialize(self.fmt, req.get_response(api))
            self._compare_resource(res, data['subnetpool'], 'subnetpool')

    def test_update_subnetpool_associate_another_address_scope(self):
        with self.address_scope(name='foo-address-scope') as addr_scope:
            address_scope_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            expected = {'address_scope_id': address_scope_id}
            initial_subnetpool = self._test_create_subnetpool(
                [subnet.cidr], expected=expected, name='foo-sp',
                min_prefixlen='21', address_scope_id=address_scope_id)

            with self.address_scope(name='foo-address-scope') as other_a_s:
                other_a_s_id = other_a_s['address_scope']['id']
                update_data = {'subnetpool': {'address_scope_id':
                                              other_a_s_id}}
                req = self.new_update_request(
                    'subnetpools', update_data,
                    initial_subnetpool['subnetpool']['id'])
                api = self._api_for_resource('subnetpools')
                res = self.deserialize(self.fmt, req.get_response(api))
                self._compare_resource(res, update_data['subnetpool'],
                                       'subnetpool')

    def _test_update_subnetpool_address_scope_notify(self, as_change=True):
        with self.address_scope(name='foo-address-scope') as addr_scope:
            foo_as_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            initial_subnetpool = self._test_create_subnetpool(
                [subnet.cidr], name='foo-sp',
                min_prefixlen='21', address_scope_id=foo_as_id)
            subnetpool_id = initial_subnetpool['subnetpool']['id']
            with self.address_scope(name='bar-address-scope') as other_as, \
                    self.network() as network:
                data = {'subnet': {
                        'network_id': network['network']['id'],
                        'subnetpool_id': subnetpool_id,
                        'prefixlen': 24,
                        'ip_version': constants.IP_VERSION_4,
                        'tenant_id': network['network']['tenant_id']}}
                req = self.new_create_request('subnets', data)
                subnet = self.deserialize(self.fmt,
                                          req.get_response(self.api))

                with mock.patch.object(registry, 'publish') as publish:
                    plugin = db_base_plugin_v2.NeutronDbPluginV2()
                    plugin.is_address_scope_owned_by_tenant = mock.Mock(
                        return_value=True)
                    plugin._validate_address_scope_id = mock.Mock()
                    ctx = context.get_admin_context()

                    bar_as_id = other_as['address_scope']['id']
                    data = {'subnetpool': {
                            'name': 'bar-sp'}}
                    if as_change:
                        data['subnetpool']['address_scope_id'] = bar_as_id

                    updated_sp = plugin.update_subnetpool(
                        ctx, subnetpool_id, data)

                    self.assertEqual('bar-sp', updated_sp['name'])
                    if as_change:
                        self.assertEqual(bar_as_id,
                                         updated_sp['address_scope_id'])
                        publish.assert_called_once_with(
                            resources.SUBNETPOOL_ADDRESS_SCOPE,
                            events.AFTER_UPDATE,
                            plugin.update_subnetpool, payload=mock.ANY)
                        payload = publish.mock_calls[0][2]['payload']
                        self.assertEqual(ctx, payload.context)
                        self.assertEqual(subnetpool_id, payload.resource_id)
                    else:
                        self.assertEqual(foo_as_id,
                                         updated_sp['address_scope_id'])
                        self.assertFalse(publish.called)

    def test_update_subnetpool_address_scope_notify(self):
        self._test_update_subnetpool_address_scope_notify()

    def test_not_update_subnetpool_address_scope_not_notify(self):
        self._test_update_subnetpool_address_scope_notify(False)

    def test_network_create_contain_address_scope_attr(self):
        with self.network() as network:
            result = self._show('networks', network['network']['id'])
            keys = [apidef.IPV4_ADDRESS_SCOPE,
                    apidef.IPV6_ADDRESS_SCOPE]
            for k in keys:
                # Correlated address scopes should initially be None
                self.assertIsNone(result['network'][k])

    def test_correlate_network_with_address_scope(self):
        with self.address_scope(name='v4-as') as v4_addr_scope, \
                self.address_scope(
                    name='v6-as',
                    ip_version=constants.IP_VERSION_6) as v6_addr_scope, \
                self.network() as network:
            v4_as_id = v4_addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            v4_subnetpool = self._test_create_subnetpool(
                [subnet.cidr], name='v4-sp',
                min_prefixlen='24', address_scope_id=v4_as_id)
            v4_subnetpool_id = v4_subnetpool['subnetpool']['id']
            v6_as_id = v6_addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('fd5c:6ee1:c7ae::/64')
            v6_subnetpool = self._test_create_subnetpool(
                [subnet.cidr], name='v6-sp',
                min_prefixlen='64', address_scope_id=v6_as_id)
            v6_subnetpool_id = v6_subnetpool['subnetpool']['id']
            data = {'subnet': {
                    'network_id': network['network']['id'],
                    'subnetpool_id': v4_subnetpool_id,
                    'ip_version': constants.IP_VERSION_4,
                    'tenant_id': network['network']['tenant_id']}}
            req = self.new_create_request('subnets', data)
            self.deserialize(self.fmt, req.get_response(self.api))
            data['subnet']['subnetpool_id'] = v6_subnetpool_id
            data['subnet']['ip_version'] = constants.IP_VERSION_6
            req = self.new_create_request('subnets', data)
            self.deserialize(self.fmt, req.get_response(self.api))
            result = self._show('networks', network['network']['id'])
            self.assertEqual(
                v4_as_id,
                result['network'][apidef.IPV4_ADDRESS_SCOPE])
            self.assertEqual(
                v6_as_id,
                result['network'][apidef.IPV6_ADDRESS_SCOPE])

    def test_delete_address_scope_in_use(self):
        with self.address_scope(name='foo-address-scope') as addr_scope:
            address_scope_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            expected = {'address_scope_id': address_scope_id}
            self._test_create_subnetpool([subnet.cidr], expected=expected,
                                         name='foo-subnetpool',
                                         min_prefixlen='21',
                                         address_scope_id=address_scope_id)
            self._delete('address-scopes', address_scope_id,
                         expected_code=webob.exc.HTTPConflict.code)

    def test_add_subnetpool_address_scope_wrong_address_family(self):
        with self.address_scope(constants.IP_VERSION_6,
                                name='foo-address-scope') as addr_scope:
            address_scope_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            self.assertRaises(webob.exc.HTTPClientError,
                              self._test_create_subnetpool,
                              [subnet.cidr], name='foo-subnetpool',
                              min_prefixlen='21',
                              address_scope_id=address_scope_id)

    def test_update_subnetpool_associate_address_scope_wrong_family(self):
        with self.address_scope(constants.IP_VERSION_6,
                                name='foo-address-scope') as addr_scope:
            address_scope_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('2001:db8::/64')
            expected = {'address_scope_id': address_scope_id}
            initial_subnetpool = self._test_create_subnetpool(
                [subnet.cidr], expected=expected, name='foo-sp',
                min_prefixlen='64', address_scope_id=address_scope_id)

            with self.address_scope(name='foo-address-scope') as other_a_s:
                other_a_s_id = other_a_s['address_scope']['id']
                update_data = {'subnetpool': {'address_scope_id':
                                              other_a_s_id}}
                req = self.new_update_request(
                    'subnetpools', update_data,
                    initial_subnetpool['subnetpool']['id'])
                api = self._api_for_resource('subnetpools')
                res = req.get_response(api)
                self.assertEqual(webob.exc.HTTPBadRequest.code,
                                 res.status_int)

    def test_create_two_subnets_different_subnetpools_same_network(self):
        with self.address_scope(constants.IP_VERSION_4,
                                name='foo-address-scope') as addr_scope:
            addr_scope = addr_scope['address_scope']
            with self.subnetpool(
                        ['10.10.0.0/16'],
                        name='subnetpool_a',
                        tenant_id=addr_scope['tenant_id'],
                        default_prefixlen=24,
                        address_scope_id=addr_scope['id']) as subnetpool_a,\
                self.subnetpool(
                         ['10.20.0.0/16'],
                         name='subnetpool_b',
                         tenant_id=addr_scope['tenant_id'],
                         default_prefixlen=24,
                         address_scope_id=addr_scope['id']) as subnetpool_b:
                subnetpool_a = subnetpool_a['subnetpool']
                subnetpool_b = subnetpool_b['subnetpool']

                with self.network(
                        tenant_id=addr_scope['tenant_id']) as network:
                    subnet_a = self._make_subnet(
                        self.fmt,
                        network,
                        constants.ATTR_NOT_SPECIFIED,
                        None,
                        subnetpool_id=subnetpool_a['id'],
                        ip_version=constants.IP_VERSION_4,
                        tenant_id=addr_scope['tenant_id'])
                    subnet_b = self._make_subnet(
                        self.fmt,
                        network,
                        constants.ATTR_NOT_SPECIFIED,
                        None,
                        subnetpool_id=subnetpool_b['id'],
                        ip_version=constants.IP_VERSION_4,
                        tenant_id=addr_scope['tenant_id'])

                    # Look up subnet counts and perform assertions
                    ctx = context.Context('', addr_scope['tenant_id'])
                    pl = directory.get_plugin()
                    total_count = pl.get_subnets_count(
                        ctx,
                        filters={'network_id':
                                 [network['network']['id']]})
                    subnets_pool_a_count = pl.get_subnets_count(
                        ctx,
                        filters={'id': [subnet_a['subnet']['id']],
                                 'subnetpool_id': [subnetpool_a['id']],
                                 'network_id': [network['network']['id']]})
                    subnets_pool_b_count = pl.get_subnets_count(
                        ctx,
                        filters={'id': [subnet_b['subnet']['id']],
                                 'subnetpool_id': [subnetpool_b['id']],
                                 'network_id': [network['network']['id']]})
                    self.assertEqual(2, total_count)
                    self.assertEqual(1, subnets_pool_a_count)
                    self.assertEqual(1, subnets_pool_b_count)

    def test_block_update_subnetpool_network_affinity(self):
        with self.address_scope(constants.IP_VERSION_4,
                                name='scope-a') as scope_a,\
            self.address_scope(constants.IP_VERSION_4,
                               name='scope-b') as scope_b:
            scope_a = scope_a['address_scope']
            scope_b = scope_b['address_scope']

            with self.subnetpool(
                        ['10.10.0.0/16'],
                        name='subnetpool_a',
                        tenant_id=scope_a['tenant_id'],
                        default_prefixlen=24,
                        address_scope_id=scope_a['id']) as subnetpool_a,\
                self.subnetpool(
                         ['10.20.0.0/16'],
                         name='subnetpool_b',
                         tenant_id=scope_a['tenant_id'],
                         default_prefixlen=24,
                         address_scope_id=scope_a['id']) as subnetpool_b:
                subnetpool_a = subnetpool_a['subnetpool']
                subnetpool_b = subnetpool_b['subnetpool']

                with self.network(
                        tenant_id=scope_a['tenant_id']) as network:
                    self._make_subnet(
                        self.fmt,
                        network,
                        constants.ATTR_NOT_SPECIFIED,
                        None,
                        subnetpool_id=subnetpool_a['id'],
                        ip_version=constants.IP_VERSION_4,
                        tenant_id=scope_a['tenant_id'])
                    self._make_subnet(
                        self.fmt,
                        network,
                        constants.ATTR_NOT_SPECIFIED,
                        None,
                        subnetpool_id=subnetpool_b['id'],
                        ip_version=constants.IP_VERSION_4,
                        tenant_id=scope_a['tenant_id'])

                    # Attempt to update subnetpool_b's address scope and
                    # assert failure.
                    data = {'subnetpool': {'address_scope_id':
                                           scope_b['id']}}
                    req = self.new_update_request('subnetpools', data,
                                                  subnetpool_b['id'])
                    api = self._api_for_resource('subnetpools')
                    res = req.get_response(api)
                    self.assertEqual(webob.exc.HTTPBadRequest.code,
                                     res.status_int)

    def test_ipv6_pd_add_non_pd_subnet_to_same_network(self):
        with self.address_scope(constants.IP_VERSION_6,
                                name='foo-address-scope') as addr_scope:
            addr_scope = addr_scope['address_scope']
            with self.subnetpool(
                        ['2001:db8:1234::/48'],
                        name='non_pd_pool',
                        tenant_id=addr_scope['tenant_id'],
                        default_prefixlen=64,
                        address_scope_id=addr_scope['id']) as non_pd_pool:
                non_pd_pool = non_pd_pool['subnetpool']

                with self.network(
                        tenant_id=addr_scope['tenant_id']) as network:
                    with self.subnet(cidr=None,
                                     network=network,
                                     ip_version=constants.IP_VERSION_6,
                                     subnetpool_id=constants.IPV6_PD_POOL_ID,
                                     ipv6_ra_mode=constants.IPV6_SLAAC,
                                     ipv6_address_mode=constants.IPV6_SLAAC):
                        res = self._create_subnet(
                            self.fmt,
                            cidr=None,
                            net_id=network['network']['id'],
                            subnetpool_id=non_pd_pool['id'],
                            tenant_id=addr_scope['tenant_id'],
                            ip_version=constants.IP_VERSION_6)
                        self.assertEqual(webob.exc.HTTPBadRequest.code,
                                         res.status_int)

    def test_ipv6_non_pd_add_pd_subnet_to_same_network(self):
        with self.address_scope(constants.IP_VERSION_6,
                                name='foo-address-scope') as addr_scope:
            addr_scope = addr_scope['address_scope']
            with self.subnetpool(
                        ['2001:db8:1234::/48'],
                        name='non_pd_pool',
                        tenant_id=addr_scope['tenant_id'],
                        default_prefixlen=64,
                        address_scope_id=addr_scope['id']) as non_pd_pool:
                non_pd_pool = non_pd_pool['subnetpool']

                with self.network(
                        tenant_id=addr_scope['tenant_id']) as network:
                    with self.subnet(cidr=None,
                                     network=network,
                                     ip_version=constants.IP_VERSION_6,
                                     subnetpool_id=non_pd_pool['id']):
                        res = self._create_subnet(
                            self.fmt,
                            cidr=None,
                            net_id=network['network']['id'],
                            tenant_id=addr_scope['tenant_id'],
                            subnetpool_id=constants.IPV6_PD_POOL_ID,
                            ip_version=constants.IP_VERSION_6,
                            ipv6_ra_mode=constants.IPV6_SLAAC,
                            ipv6_address_mode=constants.IPV6_SLAAC)
                        self.assertEqual(webob.exc.HTTPBadRequest.code,
                                         res.status_int)
