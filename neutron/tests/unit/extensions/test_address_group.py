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

from neutron_lib.api.definitions import address_group as apidef
from neutron_lib import context
import webob.exc

from neutron.db import address_group_db
from neutron.db import db_base_plugin_v2
from neutron.extensions import address_group as ag_ext
from neutron.tests.unit.db import test_db_base_plugin_v2


DB_PLUGIN_KLASS = ('neutron.tests.unit.extensions.test_address_group.'
                   'AddressGroupTestPlugin')


class AddressGroupTestExtensionManager(object):

    def get_resources(self):
        return ag_ext.Address_group.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class AddressGroupTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def _create_address_group(self, **kwargs):
        address_group = {'address_group': {}}
        for k, v in kwargs.items():
            if k != 'addresses':
                v = str(v)
            address_group['address_group'][k] = v

        req = self.new_create_request('address-groups', address_group)
        neutron_context = context.Context('', kwargs.get('tenant_id',
                                                         self._tenant_id))
        req.environ['neutron.context'] = neutron_context
        res = req.get_response(self.ext_api)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return res

    def _test_create_address_group(self, expected=None, **kwargs):
        keys = kwargs.copy()
        keys.setdefault('tenant_id', self._tenant_id)
        res = self._create_address_group(**keys)
        ag = self.deserialize(self.fmt, res)
        self._validate_resource(ag, keys, 'address_group')
        if expected:
            self._compare_resource(ag, expected, 'address_group')
        return ag

    def _test_update_address_group(self, addr_group_id, data,
                                   expected=None, tenant_id=None):
        update_req = self.new_update_request(
            'address-groups', data, addr_group_id)
        update_req.environ['neutron.context'] = context.Context(
            '', tenant_id or self._tenant_id)

        update_res = update_req.get_response(self.ext_api)
        if expected:
            addr_group = self.deserialize(self.fmt, update_res)
            self._compare_resource(addr_group, expected, 'address_group')
            return addr_group

        return update_res

    def _test_address_group_actions(self, addr_group_id, data, action,
                                    expected=None, tenant_id=None):
        act_req = self.new_action_request(
            'address-groups', data, addr_group_id, action)
        act_req.environ['neutron.context'] = context.Context(
            '', tenant_id or self._tenant_id)

        act_res = act_req.get_response(self.ext_api)
        if expected:
            addr_group = self.deserialize(self.fmt, act_res)
            self._compare_resource(addr_group, expected, 'address_group')
            return addr_group

        return act_res


class AddressGroupTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                             address_group_db.AddressGroupDbMixin):
    __native_pagination_support = True
    __native_sorting_support = True
    # address-group requires security-group extension
    supported_extension_aliases = [apidef.ALIAS, 'security-group']


class TestAddressGroup(AddressGroupTestCase):

    def setUp(self):
        plugin = DB_PLUGIN_KLASS
        ext_mgr = AddressGroupTestExtensionManager()
        super(TestAddressGroup, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def test_create_address_group_without_description_or_addresses(self):
        expected_ag = {'name': 'foo',
                       'tenant_id': self._tenant_id,
                       'description': '',
                       'addresses': []}
        self._test_create_address_group(name='foo',
                                        expected=expected_ag)

    def test_create_address_group_with_description_and_addresses(self):
        expected_ag = {'name': 'foo',
                       'description': 'bar',
                       'tenant_id': self._tenant_id,
                       'addresses': ['10.0.1.255/28', '192.168.0.1/32']}
        self._test_create_address_group(name='foo', description='bar',
                                        addresses=['10.0.1.255/28',
                                                   '192.168.0.1/32'],
                                        expected=expected_ag)

    def test_create_address_group_empty_name(self):
        expected_ag = {'name': ''}
        self._test_create_address_group(name='', expected=expected_ag)

    def test_update_address_group_name_and_description(self):
        ag = self._test_create_address_group(name='foo')
        data = {'address_group': {'name': 'bar', 'description': 'bar'}}
        self._test_update_address_group(ag['address_group']['id'],
                                        data, expected=data['address_group'])

    def test_update_address_group_addresses(self):
        ag = self._test_create_address_group(name='foo')
        data = {'address_group': {'addresses': ['10.0.0.1/32']}}
        res = self._test_update_address_group(ag['address_group']['id'], data)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_get_address_group(self):
        ag = self._test_create_address_group(name='foo')
        req = self.new_show_request('address-groups',
                                    ag['address_group']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(ag['address_group']['id'],
                         res['address_group']['id'])

    def test_list_address_groups(self):
        self._test_create_address_group(name='foo')
        self._test_create_address_group(name='bar')
        res = self._list('address-groups')
        self.assertEqual(2, len(res['address_groups']))

    def test_delete_address_group(self):
        ag = self._test_create_address_group(name='foo')
        self._delete('address-groups', ag['address_group']['id'])
        self._show('address-groups', ag['address_group']['id'],
                   expected_code=webob.exc.HTTPNotFound.code)

    def test_add_valid_addresses(self):
        ag = self._test_create_address_group(name='foo')
        data = {'addresses': ['10.0.0.1/32', '2001::/32']}
        self._test_address_group_actions(ag['address_group']['id'], data,
                                         'add_addresses', expected=data)

    def test_add_invalid_addresses(self):
        ag = self._test_create_address_group(name='foo')
        data = {'addresses': ['123456']}
        res = self._test_address_group_actions(ag['address_group']['id'],
                                               data, 'add_addresses')
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_add_duplicated_addresses(self):
        ag = self._test_create_address_group(name='foo',
                                             addresses=['10.0.0.1/32'])
        data = {'addresses': ['10.0.0.1/32']}
        res = self._test_address_group_actions(ag['address_group']['id'],
                                               data, 'add_addresses')
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_remove_valid_addresses(self):
        ag = self._test_create_address_group(name='foo',
                                             addresses=['10.0.0.1/32',
                                                        '2001::/32'])
        data = {'addresses': ['10.0.0.1/32']}
        self._test_address_group_actions(ag['address_group']['id'],
                                         data, 'remove_addresses',
                                         expected={
                                             'addresses': ['2001::/32']
                                         })

    def test_remove_absent_addresses(self):
        ag = self._test_create_address_group(name='foo',
                                             addresses=['10.0.0.1/32'])
        data = {'addresses': ['2001::/32']}
        res = self._test_address_group_actions(ag['address_group']['id'],
                                               data, 'remove_addresses')
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
