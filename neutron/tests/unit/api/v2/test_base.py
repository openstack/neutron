# Copyright (c) 2012 OpenStack Foundation.
# All Rights Reserved.
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

import os
from unittest import mock
import urllib

from neutron_lib.api import attributes
from neutron_lib.api import converters
from neutron_lib.api.definitions import address_group
from neutron_lib.api.definitions import empty_string_filtering
from neutron_lib.api.definitions import filter_validation
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import l3_ext_gw_multihoming
from neutron_lib.callbacks import registry
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib import fixture
from neutron_lib.tests.unit import fake_notifier
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_policy import policy as oslo_policy
from oslo_utils import uuidutils
import webob
from webob import exc
import webtest

from neutron.api import api_common
from neutron.api import extensions
from neutron.api.v2 import base as v2_base
from neutron.api.v2 import resource as api_resource
from neutron.api.v2 import router
from neutron.conf import quota as quota_conf
from neutron import policy
from neutron import quota
from neutron.tests import base
from neutron.tests import tools
from neutron.tests.unit import testlib_api


EXTDIR = os.path.join(base.ROOTDIR, 'unit/extensions')
NULL_QUOTA_DRIVER = 'neutron.db.quota.driver_null.DbQuotaDriverNull'

_uuid = uuidutils.generate_uuid


def _get_path(resource, id=None, action=None,
              fmt=None, endpoint=None):
    path = '/%s' % resource

    if id is not None:
        path = path + '/%s' % id

    if action is not None:
        path = path + '/%s' % action

    if endpoint is not None:
        path = path + '/%s' % endpoint

    if fmt is not None:
        path = path + '.%s' % fmt

    return path


def _get_neutron_env(tenant_id=None, as_admin=False):
    tenant_id = tenant_id or _uuid()
    roles = ['member', 'reader']
    if as_admin:
        roles.append('admin')
    return {'neutron.context': context.Context('', tenant_id, roles=roles)}


class APIv2TestBase(base.BaseTestCase):
    def setUp(self):
        super().setUp()

        plugin = 'neutron.neutron_plugin_base_v2.NeutronPluginBaseV2'
        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None
        # Create the default configurations
        self.config_parse()
        # Update the plugin
        self.setup_coreplugin(plugin, load_plugins=False)
        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()
        instance = self.plugin.return_value
        instance.supported_extension_aliases = [empty_string_filtering.ALIAS,
                                                filter_validation.ALIAS]
        instance._NeutronPluginBaseV2__native_pagination_support = True
        instance._NeutronPluginBaseV2__native_sorting_support = True
        instance._NeutronPluginBaseV2__filter_validation_support = True
        tools.make_mock_plugin_json_encodable(instance)

        api = router.APIRouter()
        self.api = webtest.TestApp(api)

        self._tenant_id = "api-test-tenant"

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', quota_conf.QUOTA_DB_DRIVER,
                              group='QUOTAS')

        # APIRouter initialization resets policy module, re-initializing it
        policy.init()

    def _post_request(self, path, initial_input, expect_errors=None,
                      req_tenant_id=None, as_admin=False):
        req_tenant_id = req_tenant_id or self._tenant_id
        return self.api.post_json(
            path, initial_input, expect_errors=expect_errors,
            extra_environ=_get_neutron_env(req_tenant_id, as_admin))

    def _put_request(self, path, initial_input, expect_errors=None,
                     req_tenant_id=None, as_admin=False):
        req_tenant_id = req_tenant_id or self._tenant_id
        return self.api.put_json(
            path, initial_input, expect_errors=expect_errors,
            extra_environ=_get_neutron_env(req_tenant_id, as_admin))

    def _delete_request(self, path, expect_errors=None,
                        req_tenant_id=None, as_admin=False):
        req_tenant_id = req_tenant_id or self._tenant_id
        return self.api.delete_json(
            path, expect_errors=expect_errors,
            extra_environ=_get_neutron_env(req_tenant_id, as_admin))


class _ArgMatcher:
    """An adapter to assist mock assertions, used to custom compare."""

    def __init__(self, cmp, obj):
        self.cmp = cmp
        self.obj = obj

    def __eq__(self, other):
        return self.cmp(self.obj, other)


def _list_cmp(l1, l2):
    return set(l1) == set(l2)


class APIv2TestCase(APIv2TestBase):

    @staticmethod
    def _get_policy_attrs(attr_info):
        policy_attrs = {name for (name, info) in attr_info.items()
                        if info.get('required_by_policy')}
        if 'tenant_id' in policy_attrs:
            policy_attrs.add('project_id')
        return sorted(policy_attrs)

    def _do_field_list(self, resource, base_fields):
        attr_info = attributes.RESOURCES[resource]
        policy_attrs = self._get_policy_attrs(attr_info)
        for name, info in attr_info.items():
            if info.get('primary_key'):
                policy_attrs.append(name)
        fields = base_fields
        fields.extend(policy_attrs)
        return fields

    def _get_collection_kwargs(self, skipargs=None, **kwargs):
        skipargs = skipargs or []
        args_list = ['filters', 'fields', 'sorts', 'limit', 'marker',
                     'page_reverse']
        args_dict = {
            arg: mock.ANY for arg in set(args_list) - set(skipargs)}
        args_dict.update(kwargs)
        return args_dict

    def test_fields(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': 'foo'})
        fields = self._do_field_list('networks', ['foo'])
        kwargs = self._get_collection_kwargs(fields=fields)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_fields_multiple(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        fields = self._do_field_list('networks', ['bar', 'foo'])
        self.api.get(_get_path('networks'), {'fields': ['foo', 'bar']})
        kwargs = self._get_collection_kwargs(fields=fields)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_fields_multiple_with_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        fields = self._do_field_list('networks', ['foo'])
        self.api.get(_get_path('networks'), {'fields': ['foo', '']})
        kwargs = self._get_collection_kwargs(fields=fields)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_fields_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': ''})
        kwargs = self._get_collection_kwargs(fields=[])
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_fields_multiple_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'fields': ['', '']})
        kwargs = self._get_collection_kwargs(fields=[])
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'name': 'bar'})
        filters = {'name': ['bar']}
        kwargs = self._get_collection_kwargs(filters=filters)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'name': ''})
        filters = {'name': ['']}
        kwargs = self._get_collection_kwargs(filters=filters)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters_multiple_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'name': ['', '']})
        filters = {'name': ['', '']}
        kwargs = self._get_collection_kwargs(filters=filters)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters_multiple_with_empty(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'name': ['bar', '']})
        filters = {'name': ['bar', '']}
        kwargs = self._get_collection_kwargs(filters=filters)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters_multiple_values(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'name': ['bar', 'bar2']})
        filters = {'name': ['bar', 'bar2']}
        kwargs = self._get_collection_kwargs(filters=filters)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters_multiple(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'name': 'bar',
                                             'tenant_id': 'bar2'})
        filters = {'name': ['bar'], 'tenant_id': ['bar2']}
        kwargs = self._get_collection_kwargs(filters=filters)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters_with_fields(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'name': 'bar', 'fields': 'foo'})
        filters = {'name': ['bar']}
        fields = self._do_field_list('networks', ['foo'])
        kwargs = self._get_collection_kwargs(filters=filters, fields=fields)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters_with_convert_to(self):
        instance = self.plugin.return_value
        instance.get_ports.return_value = []

        self.api.get(_get_path('ports'), {'admin_state_up': 'true'})
        filters = {'admin_state_up': [True]}
        kwargs = self._get_collection_kwargs(filters=filters)
        instance.get_ports.assert_called_once_with(mock.ANY, **kwargs)

    def test_filters_with_convert_list_to(self):
        instance = self.plugin.return_value
        instance.get_ports.return_value = []

        self.api.get(_get_path('ports'),
                     {'fixed_ips': ['ip_address=foo', 'subnet_id=bar']})
        filters = {'fixed_ips': {'ip_address': ['foo'], 'subnet_id': ['bar']}}
        kwargs = self._get_collection_kwargs(filters=filters)
        instance.get_ports.assert_called_once_with(mock.ANY, **kwargs)

    def test_limit(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'),
                     {'limit': '10'})
        kwargs = self._get_collection_kwargs(limit=10)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_limit_with_great_than_max_limit(self):
        cfg.CONF.set_default('pagination_max_limit', '1000')
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'),
                     {'limit': '1001'})
        kwargs = self._get_collection_kwargs(limit=1000)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_limit_with_zero(self):
        cfg.CONF.set_default('pagination_max_limit', '1000')
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'), {'limit': '0'})
        kwargs = self._get_collection_kwargs(limit=1000)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_limit_with_unspecific(self):
        cfg.CONF.set_default('pagination_max_limit', '1000')
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'))
        kwargs = self._get_collection_kwargs(limit=1000)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_limit_with_negative_value(self):
        cfg.CONF.set_default('pagination_max_limit', '1000')
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        res = self.api.get(_get_path('networks'), {'limit': -1},
                           expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_limit_with_non_integer(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        res = self.api.get(_get_path('networks'),
                           {'limit': 'abc'}, expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)
        self.assertIn('abc', res)

    def test_limit_with_infinite_pagination_max_limit(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []
        cfg.CONF.set_override('pagination_max_limit', 'Infinite')
        self.api.get(_get_path('networks'))
        kwargs = self._get_collection_kwargs(limit=None)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_limit_with_negative_pagination_max_limit(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []
        cfg.CONF.set_default('pagination_max_limit', '-1')
        self.api.get(_get_path('networks'))
        kwargs = self._get_collection_kwargs(limit=None)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_limit_with_non_integer_pagination_max_limit(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []
        cfg.CONF.set_default('pagination_max_limit', 'abc')
        self.api.get(_get_path('networks'))
        kwargs = self._get_collection_kwargs(limit=None)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_marker(self):
        cfg.CONF.set_override('pagination_max_limit', '1000')
        instance = self.plugin.return_value
        instance.get_networks.return_value = []
        marker = _uuid()
        self.api.get(_get_path('networks'),
                     {'marker': marker})
        kwargs = self._get_collection_kwargs(limit=1000, marker=marker)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_page_reverse(self):
        calls = []
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'),
                     {'page_reverse': 'True'})
        kwargs = self._get_collection_kwargs(page_reverse=True)
        calls.append(mock.call.get_networks(mock.ANY, **kwargs))
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

        instance.get_networks.reset_mock()

        self.api.get(_get_path('networks'),
                     {'page_reverse': 'False'})
        kwargs = self._get_collection_kwargs(page_reverse=False)
        calls.append(mock.call.get_networks(mock.ANY, **kwargs))
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_page_reverse_with_non_bool(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'),
                     {'page_reverse': 'abc'})
        kwargs = self._get_collection_kwargs(page_reverse=False)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_page_reverse_with_unspecific(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'))
        kwargs = self._get_collection_kwargs(page_reverse=False)
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_sort(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'),
                     {'sort_key': ['name', 'admin_state_up'],
                      'sort_dir': ['desc', 'asc']})
        kwargs = self._get_collection_kwargs(sorts=[('name', False),
                                                    ('admin_state_up', True),
                                                    ('id', True)])
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_sort_with_primary_key(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        self.api.get(_get_path('networks'),
                     {'sort_key': ['name', 'admin_state_up', 'id'],
                      'sort_dir': ['desc', 'asc', 'desc']})
        kwargs = self._get_collection_kwargs(sorts=[('name', False),
                                                    ('admin_state_up', True),
                                                    ('id', False)])
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_sort_without_direction(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        res = self.api.get(_get_path('networks'), {'sort_key': ['name']},
                           expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_sort_with_invalid_attribute(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        res = self.api.get(_get_path('networks'),
                           {'sort_key': 'abc',
                            'sort_dir': 'asc'},
                           expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_sort_with_invalid_dirs(self):
        instance = self.plugin.return_value
        instance.get_networks.return_value = []

        res = self.api.get(_get_path('networks'),
                           {'sort_key': 'name',
                            'sort_dir': 'abc'},
                           expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_emulated_sort(self):
        instance = self.plugin.return_value
        instance._NeutronPluginBaseV2__native_pagination_support = False
        instance._NeutronPluginBaseV2__native_sorting_support = False
        instance.get_networks.return_value = []
        api = webtest.TestApp(router.APIRouter())
        api.get(_get_path('networks'), {'sort_key': ['name', 'status'],
                                        'sort_dir': ['desc', 'asc']})
        kwargs = self._get_collection_kwargs(
            skipargs=['sorts', 'limit', 'marker', 'page_reverse'])
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_emulated_sort_without_sort_field(self):
        instance = self.plugin.return_value
        instance._NeutronPluginBaseV2__native_pagination_support = False
        instance._NeutronPluginBaseV2__native_sorting_support = False
        instance.get_networks.return_value = []
        api = webtest.TestApp(router.APIRouter())
        api.get(_get_path('networks'), {'sort_key': ['name', 'status'],
                                        'sort_dir': ['desc', 'asc'],
                                        'fields': ['subnets']})
        kwargs = self._get_collection_kwargs(
            skipargs=['sorts', 'limit', 'marker', 'page_reverse'],
            fields=_ArgMatcher(_list_cmp, ['name',
                                           'status',
                                           'id',
                                           'subnets',
                                           'shared',
                                           'project_id',
                                           'tenant_id']))
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_emulated_pagination(self):
        instance = self.plugin.return_value
        instance._NeutronPluginBaseV2__native_pagination_support = False
        instance.get_networks.return_value = []
        api = webtest.TestApp(router.APIRouter())
        api.get(_get_path('networks'), {'limit': 10,
                                        'marker': 'foo',
                                        'page_reverse': False})
        kwargs = self._get_collection_kwargs(skipargs=['limit',
                                                       'marker',
                                                       'page_reverse'])
        instance.get_networks.assert_called_once_with(mock.ANY, **kwargs)

    def test_native_pagination_without_native_sorting(self):
        instance = self.plugin.return_value
        instance._NeutronPluginBaseV2__native_sorting_support = False
        self.assertRaises(n_exc.Invalid, router.APIRouter)


# Note: since all resources use the same controller and validation
# logic, we actually get really good coverage from testing just networks.
class JSONV2TestCase(APIv2TestBase, testlib_api.WebTestCase):

    def _test_list(self, req_tenant_id, real_tenant_id):
        env = {}
        if req_tenant_id:
            env = _get_neutron_env(req_tenant_id)
        input_dict = {'id': uuidutils.generate_uuid(),
                      'name': 'net1',
                      'admin_state_up': True,
                      'status': "ACTIVE",
                      'project_id': real_tenant_id,
                      'shared': False,
                      'subnets': []}
        instance = self.plugin.return_value
        instance.get_networks.return_value = [input_dict]

        res = self.api.get(_get_path('networks',
                                     fmt=self.fmt), extra_environ=env)
        res = self.deserialize(res)
        self.assertIn('networks', res)
        if not req_tenant_id or req_tenant_id == real_tenant_id:
            # expect full list returned
            self.assertEqual(1, len(res['networks']))
            output_dict = res['networks'][0]
            input_dict['shared'] = False
            self.assertEqual(len(input_dict), len(output_dict))
            for k, v in input_dict.items():
                self.assertEqual(v, output_dict[k])
        else:
            # expect no results
            self.assertEqual(0, len(res['networks']))

    def test_list_noauth(self):
        self._test_list(None, _uuid())

    def test_list_keystone(self):
        tenant_id = _uuid()
        self._test_list(tenant_id, tenant_id)

    def test_list_keystone_bad(self):
        tenant_id = _uuid()
        self._test_list(tenant_id + "bad", tenant_id)

    def test_list_pagination(self):
        id1 = str(_uuid())
        id2 = str(_uuid())
        input_dict1 = {'id': id1,
                       'name': 'net1',
                       'admin_state_up': True,
                       'status': "ACTIVE",
                       'tenant_id': '',
                       'shared': False,
                       'subnets': []}
        input_dict2 = {'id': id2,
                       'name': 'net2',
                       'admin_state_up': True,
                       'status': "ACTIVE",
                       'tenant_id': '',
                       'shared': False,
                       'subnets': []}
        return_value = [input_dict1, input_dict2]
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_value
        params = {'limit': ['2'],
                  'marker': [str(_uuid())],
                  'sort_key': ['name'],
                  'sort_dir': ['asc']}
        res = self.api.get(_get_path('networks'),
                           params=params).json

        self.assertEqual(2, len(res['networks']))
        self.assertEqual(sorted([id1, id2]),
                         sorted([res['networks'][0]['id'],
                                res['networks'][1]['id']]))

        self.assertIn('networks_links', res)
        next_links = []
        previous_links = []
        for r in res['networks_links']:
            if r['rel'] == 'next':
                next_links.append(r)
            if r['rel'] == 'previous':
                previous_links.append(r)
        self.assertEqual(1, len(next_links))
        self.assertEqual(1, len(previous_links))

        url = urllib.parse.urlparse(next_links[0]['href'])
        self.assertEqual(url.path, _get_path('networks'))
        params['marker'] = [id2]
        self.assertEqual(params, urllib.parse.parse_qs(url.query))

        url = urllib.parse.urlparse(previous_links[0]['href'])
        self.assertEqual(url.path, _get_path('networks'))
        params['marker'] = [id1]
        params['page_reverse'] = ['True']
        self.assertEqual(params, urllib.parse.parse_qs(url.query))

    def test_list_pagination_with_last_page(self):
        id = str(_uuid())
        input_dict = {'id': id,
                      'name': 'net1',
                      'admin_state_up': True,
                      'status': "ACTIVE",
                      'tenant_id': '',
                      'shared': False,
                      'subnets': []}
        return_value = [input_dict]
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_value
        params = {'limit': ['2'],
                  'marker': str(_uuid())}
        res = self.api.get(_get_path('networks'),
                           params=params).json

        self.assertEqual(1, len(res['networks']))
        self.assertEqual(id, res['networks'][0]['id'])

        self.assertIn('networks_links', res)
        previous_links = []
        for r in res['networks_links']:
            self.assertNotEqual(r['rel'], 'next')
            if r['rel'] == 'previous':
                previous_links.append(r)
        self.assertEqual(1, len(previous_links))

        url = urllib.parse.urlparse(previous_links[0]['href'])
        self.assertEqual(url.path, _get_path('networks'))
        expect_params = params.copy()
        expect_params['marker'] = [id]
        expect_params['page_reverse'] = ['True']
        self.assertEqual(expect_params, urllib.parse.parse_qs(url.query))

    def test_list_pagination_with_empty_page(self):
        return_value = []
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_value
        params = {'limit': ['2'],
                  'marker': str(_uuid())}
        res = self.api.get(_get_path('networks'),
                           params=params).json

        self.assertEqual([], res['networks'])

        previous_links = []
        if 'networks_links' in res:
            for r in res['networks_links']:
                self.assertNotEqual(r['rel'], 'next')
                if r['rel'] == 'previous':
                    previous_links.append(r)
        self.assertEqual(1, len(previous_links))

        url = urllib.parse.urlparse(previous_links[0]['href'])
        self.assertEqual(url.path, _get_path('networks'))
        expect_params = params.copy()
        del expect_params['marker']
        expect_params['page_reverse'] = ['True']
        self.assertEqual(expect_params, urllib.parse.parse_qs(url.query))

    def test_list_pagination_reverse_with_last_page(self):
        id = str(_uuid())
        input_dict = {'id': id,
                      'name': 'net1',
                      'admin_state_up': True,
                      'status': "ACTIVE",
                      'tenant_id': '',
                      'shared': False,
                      'subnets': []}
        return_value = [input_dict]
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_value
        params = {'limit': ['2'],
                  'marker': [str(_uuid())],
                  'page_reverse': ['True']}
        res = self.api.get(_get_path('networks'),
                           params=params).json

        self.assertEqual(len(res['networks']), 1)
        self.assertEqual(id, res['networks'][0]['id'])

        self.assertIn('networks_links', res)
        next_links = []
        for r in res['networks_links']:
            self.assertNotEqual(r['rel'], 'previous')
            if r['rel'] == 'next':
                next_links.append(r)
        self.assertEqual(1, len(next_links))

        url = urllib.parse.urlparse(next_links[0]['href'])
        self.assertEqual(url.path, _get_path('networks'))
        expected_params = params.copy()
        del expected_params['page_reverse']
        expected_params['marker'] = [id]
        self.assertEqual(expected_params,
                         urllib.parse.parse_qs(url.query))

    def test_list_pagination_reverse_with_empty_page(self):
        return_value = []
        instance = self.plugin.return_value
        instance.get_networks.return_value = return_value
        params = {'limit': ['2'],
                  'marker': [str(_uuid())],
                  'page_reverse': ['True']}
        res = self.api.get(_get_path('networks'),
                           params=params).json
        self.assertEqual([], res['networks'])

        next_links = []
        if 'networks_links' in res:
            for r in res['networks_links']:
                self.assertNotEqual(r['rel'], 'previous')
                if r['rel'] == 'next':
                    next_links.append(r)
        self.assertEqual(1, len(next_links))

        url = urllib.parse.urlparse(next_links[0]['href'])
        self.assertEqual(url.path, _get_path('networks'))
        expect_params = params.copy()
        del expect_params['marker']
        del expect_params['page_reverse']
        self.assertEqual(expect_params, urllib.parse.parse_qs(url.query))

    def test_create(self):
        net_id = _uuid()
        data = {'network': {'name': 'net1', 'admin_state_up': True,
                            'tenant_id': _uuid()}}
        return_value = {'subnets': [], 'status': "ACTIVE",
                        'id': net_id}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value
        instance.get_networks_count.return_value = 0

        res = self.api.post(_get_path('networks', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/' + self.fmt)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('network', res)
        net = res['network']
        self.assertEqual(net_id, net['id'])
        self.assertEqual("ACTIVE", net['status'])

    def test_create_use_defaults(self):
        net_id = _uuid()
        tenant_id = _uuid()

        initial_input = {'network': {'name': 'net1',
                                     'tenant_id': tenant_id,
                                     'project_id': tenant_id}}
        full_input = {'network': {'admin_state_up': True,
                                  'shared': False}}
        full_input['network'].update(initial_input['network'])

        return_value = {'id': net_id, 'status': "ACTIVE"}
        return_value.update(full_input['network'])

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value
        instance.get_networks_count.return_value = 0

        res = self.api.post(_get_path('networks', fmt=self.fmt),
                            self.serialize(initial_input),
                            content_type='application/' + self.fmt)
        instance.create_network.assert_called_with(mock.ANY,
                                                   network=full_input)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('network', res)
        net = res['network']
        self.assertEqual(net_id, net['id'])
        self.assertTrue(net['admin_state_up'])
        self.assertEqual("ACTIVE", net['status'])

    def test_create_no_keystone_env(self):
        data = {'name': 'net1'}
        self._test_create_failure_bad_request('networks', data)

    def test_create_with_keystone_env(self):
        tenant_id = _uuid()
        net_id = _uuid()
        env = _get_neutron_env(tenant_id)
        # tenant_id should be fetched from env
        initial_input = {'network': {'name': 'net1'}}
        full_input = {'network': {'admin_state_up': True,
                      'shared': False, 'tenant_id': tenant_id,
                                  'project_id': tenant_id}}
        full_input['network'].update(initial_input['network'])

        return_value = {'id': net_id, 'status': "ACTIVE"}
        return_value.update(full_input['network'])

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value
        instance.get_networks_count.return_value = 0

        res = self.api.post(_get_path('networks', fmt=self.fmt),
                            self.serialize(initial_input),
                            content_type='application/' + self.fmt,
                            extra_environ=env)

        instance.create_network.assert_called_with(mock.ANY,
                                                   network=full_input)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)

    def test_create_bad_keystone_tenant(self):
        tenant_id = _uuid()
        data = {'network': {'name': 'net1', 'tenant_id': tenant_id}}
        env = {'neutron.context': context.Context('', tenant_id + "bad")}
        self._test_create_failure_bad_request('networks', data,
                                              extra_environ=env)

    def test_create_no_body(self):
        data = {'whoa': None}
        self._test_create_failure_bad_request('networks', data)

    def test_create_body_string_not_json(self):
        data = 'a string'
        self._test_create_failure_bad_request('networks', data)

    def test_create_body_boolean_not_json(self):
        data = True
        self._test_create_failure_bad_request('networks', data)

    def test_create_no_resource(self):
        data = {}
        self._test_create_failure_bad_request('networks', data)

    def test_create_object_string_not_json(self):
        data = {'network': 'a string'}
        self._test_create_failure_bad_request('networks', data)

    def test_create_object_boolean_not_json(self):
        data = {'network': True}
        self._test_create_failure_bad_request('networks', data)

    def test_create_missing_attr(self):
        data = {'port': {'what': 'who', 'tenant_id': _uuid()}}
        self._test_create_failure_bad_request('ports', data)

    def test_create_readonly_attr(self):
        data = {'network': {'name': 'net1', 'tenant_id': _uuid(),
                            'status': "ACTIVE"}}
        self._test_create_failure_bad_request('networks', data)

    def test_create_with_too_long_name(self):
        data = {'network': {'name': "12345678" * 32,
                            'admin_state_up': True,
                            'tenant_id': _uuid()}}
        res = self.api.post(_get_path('networks', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/' + self.fmt,
                            expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_create_bulk(self):
        data = {'networks': [{'name': 'net1',
                              'admin_state_up': True,
                              'tenant_id': _uuid()},
                             {'name': 'net2',
                              'admin_state_up': True,
                              'tenant_id': _uuid()}]}

        def side_effect(context, network):
            net = network.copy()
            net['network'].update({'subnets': []})
            return net['network']

        instance = self.plugin.return_value
        instance.create_network.side_effect = side_effect
        instance.get_networks_count.return_value = 0
        res = self.api.post(_get_path('networks', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/' + self.fmt)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)

    def _test_create_failure_bad_request(self, resource, data, **kwargs):
        res = self.api.post(_get_path(resource, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/' + self.fmt,
                            expect_errors=True, **kwargs)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_create_bulk_networks_none(self):
        self._test_create_failure_bad_request('networks', {'networks': None})

    def test_create_bulk_networks_empty_list(self):
        self._test_create_failure_bad_request('networks', {'networks': []})

    def test_create_bulk_missing_attr(self):
        data = {'ports': [{'what': 'who', 'tenant_id': _uuid()}]}
        self._test_create_failure_bad_request('ports', data)

    def test_create_bulk_partial_body(self):
        data = {'ports': [{'device_id': 'device_1',
                           'tenant_id': _uuid()},
                          {'tenant_id': _uuid()}]}
        self._test_create_failure_bad_request('ports', data)

    def test_create_attr_not_specified(self):
        net_id = _uuid()
        tenant_id = _uuid()
        device_id = _uuid()
        initial_input = {'port': {'name': '', 'network_id': net_id,
                                  'tenant_id': tenant_id,
                                  'project_id': tenant_id,
                                  'device_id': device_id,
                                  'admin_state_up': True}}
        full_input = {'port': {'admin_state_up': True,
                               'mac_address': constants.ATTR_NOT_SPECIFIED,
                               'fixed_ips': constants.ATTR_NOT_SPECIFIED,
                               'device_owner': ''}}
        full_input['port'].update(initial_input['port'])
        return_value = {'id': _uuid(), 'status': 'ACTIVE',
                        'admin_state_up': True,
                        'mac_address': 'ca:fe:de:ad:be:ef',
                        'device_id': device_id,
                        'device_owner': ''}
        return_value.update(initial_input['port'])

        instance = self.plugin.return_value
        instance.get_network.return_value = {
            'tenant_id': str(tenant_id)
        }
        instance.get_ports_count.return_value = 1
        instance.create_port.return_value = return_value
        res = self.api.post(_get_path('ports', fmt=self.fmt),
                            self.serialize(initial_input),
                            content_type='application/' + self.fmt)
        instance.create_port.assert_called_with(mock.ANY, port=full_input)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port', res)
        port = res['port']
        self.assertEqual(net_id, port['network_id'])
        self.assertEqual('ca:fe:de:ad:be:ef', port['mac_address'])

    def test_create_return_extra_attr(self):
        net_id = _uuid()
        project_id = _uuid()
        data = {'network': {'name': 'net1', 'admin_state_up': True,
                            'tenant_id': project_id}}
        return_value = {'subnets': [], 'status': "ACTIVE",
                        'id': net_id, 'v2attrs:something': "123"}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value
        instance.get_networks_count.return_value = 0

        res = self.api.post(_get_path('networks', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/' + self.fmt,
                            extra_environ=_get_neutron_env(project_id))
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('network', res)
        net = res['network']
        self.assertEqual(net_id, net['id'])
        self.assertEqual("ACTIVE", net['status'])
        self.assertNotIn('v2attrs:something', net)

    def test_fields(self):
        project_id = _uuid()
        return_value = {'name': 'net1', 'admin_state_up': True,
                        'project_id': project_id, 'subnets': []}

        instance = self.plugin.return_value
        instance.get_network.return_value = return_value

        self.api.get(_get_path('networks',
                               id=uuidutils.generate_uuid(),
                               fmt=self.fmt),
                     extra_environ=_get_neutron_env(project_id))

    def _test_delete(self, req_tenant_id, real_tenant_id, expected_code,
                     expect_errors=False):
        env = {}
        if req_tenant_id:
            env = _get_neutron_env(req_tenant_id)
        instance = self.plugin.return_value
        instance.get_network.return_value = {'project_id': real_tenant_id,
                                             'shared': False}
        instance.delete_network.return_value = None

        res = self.api.delete(_get_path('networks',
                                        id=uuidutils.generate_uuid(),
                                        fmt=self.fmt),
                              extra_environ=env,
                              expect_errors=expect_errors)
        self.assertEqual(expected_code, res.status_int)

    def test_delete_noauth(self):
        self._test_delete(None, _uuid(), exc.HTTPNoContent.code)

    def test_delete_keystone(self):
        tenant_id = _uuid()
        self._test_delete(tenant_id, tenant_id, exc.HTTPNoContent.code)

    def test_delete_keystone_bad_tenant(self):
        tenant_id = _uuid()
        self._test_delete(tenant_id + "bad", tenant_id,
                          exc.HTTPNotFound.code, expect_errors=True)

    def _test_get(self, req_tenant_id, real_tenant_id, expected_code,
                  expect_errors=False):
        shared = req_tenant_id and req_tenant_id.endswith('another')
        env = {}
        if req_tenant_id:
            env = _get_neutron_env(req_tenant_id)

        data = {'project_id': real_tenant_id, 'shared': shared}
        instance = self.plugin.return_value
        instance.get_network.return_value = data

        res = self.api.get(_get_path('networks',
                                     id=uuidutils.generate_uuid(),
                                     fmt=self.fmt),
                           extra_environ=env,
                           expect_errors=expect_errors)
        self.assertEqual(expected_code, res.status_int)
        return res

    def test_get_noauth(self):
        self._test_get(None, _uuid(), 200)

    def test_get_keystone(self):
        tenant_id = _uuid()
        self._test_get(tenant_id, tenant_id, 200)

    def test_get_keystone_bad_tenant(self):
        tenant_id = _uuid()
        self._test_get(tenant_id + "bad", tenant_id,
                       exc.HTTPNotFound.code, expect_errors=True)

    def test_get_keystone_shared_network(self):
        tenant_id = _uuid()
        self._test_get(tenant_id + "another", tenant_id, 200)

    def test_get_keystone_strip_admin_only_attribute(self):
        tenant_id = _uuid()
        # Inject rule in policy engine
        rules = oslo_policy.Rules.from_dict(
            {'get_network:name': "rule:admin_only"})
        policy.set_rules(rules, overwrite=False)
        res = self._test_get(tenant_id, tenant_id, 200)
        res = self.deserialize(res)
        self.assertNotIn('name', res['network'])

    def _test_update(self, req_tenant_id, real_tenant_id, expected_code,
                     expect_errors=False):
        env = {}
        if req_tenant_id:
            env = _get_neutron_env(req_tenant_id)
        # leave out 'name' field intentionally
        data = {'network': {'admin_state_up': True}}
        return_value = {'subnets': []}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.get_network.return_value = {'project_id': real_tenant_id,
                                             'shared': False}
        instance.update_network.return_value = return_value

        res = self.api.put(_get_path('networks',
                                     id=uuidutils.generate_uuid(),
                                     fmt=self.fmt),
                           self.serialize(data),
                           extra_environ=env,
                           expect_errors=expect_errors)
        #  Ensure id attribute is included in fields returned by GET call
        #  in update procedure.
        self.assertEqual(1, instance.get_network.call_count)
        self.assertIn('id', instance.get_network.call_args[1]['fields'])
        self.assertEqual(res.status_int, expected_code)

    def test_update_noauth(self):
        self._test_update(None, _uuid(), 200)

    def test_update_keystone(self):
        tenant_id = _uuid()
        self._test_update(tenant_id, tenant_id, 200)

    def test_update_keystone_bad_tenant(self):
        tenant_id = _uuid()
        self._test_update(tenant_id + "bad", tenant_id,
                          exc.HTTPNotFound.code, expect_errors=True)

    def test_update_keystone_no_tenant(self):
        tenant_id = _uuid()
        self._test_update(tenant_id, None,
                          exc.HTTPNotFound.code, expect_errors=True)

    def test_update_readonly_field(self):
        data = {'network': {'status': "NANANA"}}
        res = self.api.put(_get_path('networks', id=_uuid()),
                           self.serialize(data),
                           content_type='application/' + self.fmt,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_invalid_attribute_field(self):
        data = {'network': {'invalid_key1': "foo1", 'invalid_key2': "foo2"}}
        res = self.api.put(_get_path('networks', id=_uuid()),
                           self.serialize(data),
                           content_type='application/' + self.fmt,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_retry_on_index(self):
        instance = self.plugin.return_value
        instance.get_networks.side_effect = [db_exc.RetryRequest(None), []]
        api = webtest.TestApp(router.APIRouter())
        api.get(_get_path('networks', fmt=self.fmt))
        self.assertTrue(instance.get_networks.called)

    def test_retry_on_show(self):
        instance = self.plugin.return_value
        instance.get_network.side_effect = [db_exc.RetryRequest(None), {}]
        api = webtest.TestApp(router.APIRouter())
        api.get(_get_path('networks', _uuid(), fmt=self.fmt))
        self.assertTrue(instance.get_network.called)


# Note: since all resources use the same controller and validation
# logic, we actually get really good coverage from testing just networks.
class V2Views(base.BaseTestCase):
    def _view(self, keys, collection, resource):
        data = {key: 'value' for key in keys}
        data['fake'] = 'value'
        attr_info = attributes.RESOURCES[collection]
        controller = v2_base.Controller(None, collection, resource, attr_info)
        res = controller._view(context.get_admin_context(), data)
        self.assertNotIn('fake', res)
        for key in keys:
            self.assertIn(key, res)

    def test_network(self):
        keys = ('id', 'name', 'subnets', 'admin_state_up', 'status',
                'tenant_id')
        self._view(keys, 'networks', 'network')

    def test_port(self):
        keys = ('id', 'network_id', 'mac_address', 'fixed_ips',
                'device_id', 'admin_state_up', 'tenant_id', 'status')
        self._view(keys, 'ports', 'port')

    def test_subnet(self):
        keys = ('id', 'network_id', 'tenant_id', 'gateway_ip',
                'ip_version', 'cidr', 'enable_dhcp')
        self._view(keys, 'subnets', 'subnet')


class NotificationTest(APIv2TestBase):

    def setUp(self):
        super().setUp()
        fake_notifier.reset()
        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', NULL_QUOTA_DRIVER,
                              group='QUOTAS')

    def _resource_op_notifier(self, opname, resource, expected_errors=False):
        tenant_id = _uuid()
        network_obj = {'name': 'myname',
                       'project_id': tenant_id}
        initial_input = {resource: network_obj}
        instance = self.plugin.return_value
        instance.get_network.return_value = network_obj
        instance.get_networks_count.return_value = 0
        expected_code = exc.HTTPCreated.code
        if opname == 'create':
            instance.create_network.return_value = network_obj
            res = self._post_request(
                _get_path('networks'),
                initial_input, expect_errors=expected_errors,
                req_tenant_id=tenant_id)
        if opname == 'update':
            instance.update_network.return_value = network_obj
            op_input = {resource: {'name': 'myname'}}
            res = self._put_request(
                _get_path('networks', id=tenant_id),
                op_input, expect_errors=expected_errors,
                req_tenant_id=tenant_id)
            expected_code = exc.HTTPOk.code
        if opname == 'delete':
            res = self._delete_request(
                _get_path('networks', id=tenant_id),
                expect_errors=expected_errors,
                req_tenant_id=tenant_id)
            expected_code = exc.HTTPNoContent.code

        expected_events = ('.'.join([resource, opname, "start"]),
                           '.'.join([resource, opname, "end"]))
        self.assertEqual(len(expected_events),
                         len(fake_notifier.NOTIFICATIONS))
        for msg, event in zip(fake_notifier.NOTIFICATIONS, expected_events):
            self.assertEqual('INFO', msg['priority'])
            self.assertEqual(event, msg['event_type'])
            if opname == 'delete' and event == 'network.delete.end':
                self.assertIn('payload', msg)
                resource = msg['payload']
                self.assertIn('network_id', resource)
                self.assertIn('network', resource)

        self.assertEqual(expected_code, res.status_int)

    def test_network_create_notifier(self):
        self._resource_op_notifier('create', 'network')

    def test_network_delete_notifier(self):
        self._resource_op_notifier('delete', 'network')

    def test_network_update_notifier(self):
        self._resource_op_notifier('update', 'network')


class RegistryNotificationTest(APIv2TestBase):

    def setUp(self):
        super().setUp()
        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', NULL_QUOTA_DRIVER,
                              group='QUOTAS')

    def _test_registry_publish(self, opname, resource, initial_input=None):
        instance = self.plugin.return_value
        instance.get_networks.return_value = initial_input
        instance.get_networks_count.return_value = 0
        expected_code = exc.HTTPCreated.code
        with mock.patch.object(registry, 'publish') as publish:
            if opname == 'create':
                instance.create_network.return_value = initial_input
                res = self.api.post_json(
                    _get_path('networks'),
                    initial_input)
            if opname == 'update':
                instance.update_network.return_value = initial_input
                res = self.api.put_json(
                    _get_path('networks', id=_uuid()),
                    initial_input)
                expected_code = exc.HTTPOk.code
            if opname == 'delete':
                res = self.api.delete(_get_path('networks', id=_uuid()))
                expected_code = exc.HTTPNoContent.code
            self.assertTrue(publish.called)
        self.assertEqual(expected_code, res.status_int)

    def test_network_create_registry_publish(self):
        input = {'network': {'name': 'net',
                             'tenant_id': _uuid()}}
        self._test_registry_publish('create', 'network', input)

    def test_network_delete_registry_publish(self):
        self._test_registry_publish('delete', 'network')

    def test_network_update_registry_publish(self):
        input = {'network': {'name': 'net'}}
        self._test_registry_publish('update', 'network', input)

    def test_networks_create_bulk_registry_publish(self):
        input = {'networks': [{'name': 'net1',
                               'tenant_id': _uuid()},
                              {'name': 'net2',
                               'tenant_id': _uuid()}]}
        self._test_registry_publish('create', 'network', input)


class QuotaTest(APIv2TestBase):
    """This class checks the quota enforcement API, regardless of the driver"""

    def test_create_network_quota_exceeded(self):
        initial_input = {'network': {'name': 'net1', 'tenant_id': _uuid()}}
        instance = self.plugin.return_value
        instance.create_network.return_value = initial_input
        with mock.patch.object(quota.QUOTAS, 'make_reservation',
                               side_effect=n_exc.OverQuota(overs='network')):
            res = self.api.post_json(
                _get_path('networks'), initial_input, expect_errors=True)
        self.assertIn("Quota exceeded for resources",
                      res.json['NeutronError']['message'])

    def test_create_network_quota_without_limit(self):
        initial_input = {'network': {'name': 'net1', 'tenant_id': _uuid()}}
        instance = self.plugin.return_value
        instance.create_network.return_value = initial_input
        with mock.patch.object(quota.QUOTAS, 'make_reservation'), \
                mock.patch.object(quota.QUOTAS, 'commit_reservation'):
            res = self.api.post_json(
                _get_path('networks'), initial_input)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)


class ExtensionTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        plugin = 'neutron.neutron_plugin_base_v2.NeutronPluginBaseV2'
        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        self.useFixture(fixture.APIDefinitionFixture())

        # Create the default configurations
        self.config_parse()

        # Update the plugin and extensions path
        self.setup_coreplugin(plugin, load_plugins=False)
        cfg.CONF.set_override('api_extensions_path', EXTDIR)

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()

        # Instantiate mock plugin and enable the V2attributes extension
        self.plugin.return_value.supported_extension_aliases = ["v2attrs"]

        api = router.APIRouter()
        self.api = webtest.TestApp(api)

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', NULL_QUOTA_DRIVER,
                              group='QUOTAS')

    def test_extended_create(self):
        net_id = _uuid()
        tenant_id = _uuid()
        initial_input = {'network': {'name': 'net1', 'tenant_id': tenant_id,
                                     'project_id': tenant_id,
                                     'v2attrs:something_else': "abc"}}
        data = {'network': {'admin_state_up': True, 'shared': False}}
        data['network'].update(initial_input['network'])

        return_value = {'subnets': [], 'status': "ACTIVE",
                        'id': net_id,
                        'v2attrs:something': "123"}
        return_value.update(data['network'].copy())

        instance = self.plugin.return_value
        instance.create_network.return_value = return_value
        instance.get_networks_count.return_value = 0

        res = self.api.post_json(
            _get_path('networks'), initial_input,
            extra_environ=_get_neutron_env(tenant_id))

        instance.create_network.assert_called_with(mock.ANY,
                                                   network=data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        self.assertIn('network', res.json)
        net = res.json['network']
        self.assertEqual(net_id, net['id'])
        self.assertEqual("ACTIVE", net['status'])
        self.assertEqual("123", net['v2attrs:something'])
        self.assertNotIn('v2attrs:something_else', net)


class TestSubresourcePlugin:
    def get_network_dummies(self, context, network_id,
                            filters=None, fields=None):
        return []

    def get_network_dummy(self, context, id, network_id,
                          fields=None):
        return {}

    def create_network_dummy(self, context, network_id, dummy):
        return {}

    def update_network_dummy(self, context, id, network_id, dummy):
        return {}

    def delete_network_dummy(self, context, id, network_id):
        return

    def mactions(self, context, id, network_id):
        return


class ListArgsTestCase(base.BaseTestCase):
    def test_list_args(self):
        path = '/?fields=4&foo=3&fields=2&bar=1'
        request = webob.Request.blank(path)
        expect_val = ['2', '4']
        actual_val = api_common.list_args(request, 'fields')
        self.assertEqual(expect_val, sorted(actual_val))

    def test_list_args_with_empty(self):
        path = '/?foo=4&bar=3&baz=2&qux=1'
        request = webob.Request.blank(path)
        self.assertEqual([], api_common.list_args(request, 'fields'))


class SortingTestCase(base.BaseTestCase):
    def test_get_sorts(self):
        path = '/?sort_key=foo&sort_dir=desc&sort_key=bar&sort_dir=asc'
        request = webob.Request.blank(path)
        attr_info = {
            'foo': {'key': 'val', 'is_sort_key': True},
            'bar': {'key': 'val', 'is_sort_key': True}
        }
        expect_val = [('foo', False), ('bar', True)]
        actual_val = api_common.get_sorts(request, attr_info)
        self.assertEqual(expect_val, actual_val)

    def test_get_sorts_with_project_id(self):
        path = '/?sort_key=project_id&sort_dir=desc'
        request = webob.Request.blank(path)
        attr_info = {'tenant_id': {'key': 'val', 'is_sort_key': True}}
        expect_val = [('project_id', False)]
        actual_val = api_common.get_sorts(request, attr_info)
        self.assertEqual(expect_val, actual_val)

    def test_get_sorts_with_non_sort_key(self):
        path = '/?sort_key=created_at&sort_dir=desc'
        request = webob.Request.blank(path)
        attr_info = {
            'foo': {'key': 'val', 'is_sort_key': True},
            'bar': {'key': 'val', 'is_sort_key': True},
            'created_at': {'key': 'val'}
        }
        self.assertRaises(exc.HTTPBadRequest,
                          api_common.get_sorts,
                          request, attr_info)


class FiltersTestCase(base.BaseTestCase):
    def test_all_skip_args(self):
        path = '/?fields=4&fields=3&fields=2&fields=1'
        request = webob.Request.blank(path)
        self.assertEqual({}, api_common.get_filters(request, {},
                                                    ["fields"]))

    @mock.patch('neutron.api.api_common.is_empty_string_filtering_supported',
                return_value=False)
    def test_blank_values(self, mock_is_supported):
        path = '/?foo=&bar=&baz=&qux='
        request = webob.Request.blank(path)
        self.assertEqual({}, api_common.get_filters(request, {}))

    @mock.patch('neutron.api.api_common.is_empty_string_filtering_supported',
                return_value=True)
    def test_blank_values_with_filtering_supported(self, mock_is_supported):
        path = '/?foo=&bar=&baz=&qux='
        request = webob.Request.blank(path)
        self.assertEqual({'foo': [''], 'bar': [''], 'baz': [''], 'qux': ['']},
                         api_common.get_filters(request, {}))

    def test_no_attr_info(self):
        path = '/?foo=4&bar=3&baz=2&qux=1'
        request = webob.Request.blank(path)
        expect_val = {'foo': ['4'], 'bar': ['3'], 'baz': ['2'], 'qux': ['1']}
        actual_val = api_common.get_filters(request, {})
        self.assertEqual(expect_val, actual_val)

    def test_attr_info_with_project_info_populated(self):
        path = '/?foo=4&bar=3&baz=2&qux=1'
        request = webob.Request.blank(path)
        attr_info = {'tenant_id': {'key': 'val'}}
        expect_val = {'foo': ['4'], 'bar': ['3'], 'baz': ['2'], 'qux': ['1']}
        actual_val = api_common.get_filters(request, attr_info)
        self.assertEqual(expect_val, actual_val)
        expect_attr_info = {'tenant_id': {'key': 'val'},
                            'project_id': {'key': 'val'}}
        self.assertEqual(expect_attr_info, attr_info)

    @mock.patch('neutron.api.api_common.is_filter_validation_enabled',
                return_value=True)
    def test_attr_info_with_filter_validation(self, mock_validation_enabled):
        attr_info = {}
        self._test_attr_info(attr_info)

        attr_info = {'foo': {}}
        self._test_attr_info(attr_info)

        attr_info = {'foo': {'is_filter': False}}
        self._test_attr_info(attr_info)

        attr_info = {'foo': {'is_filter': False}, 'bar': {'is_filter': True},
                     'baz': {'is_filter': True}, 'qux': {'is_filter': True}}
        self._test_attr_info(attr_info)

        attr_info = {'foo': {'is_filter': True}, 'bar': {'is_filter': True},
                     'baz': {'is_filter': True}, 'qux': {'is_filter': True}}
        expect_val = {'foo': ['4'], 'bar': ['3'], 'baz': ['2'], 'qux': ['1']}
        self._test_attr_info(attr_info, expect_val)

        attr_info = {'foo': {'is_filter': True}, 'bar': {'is_filter': True},
                     'baz': {'is_filter': True}, 'qux': {'is_filter': True},
                     'quz': {}}
        expect_val = {'foo': ['4'], 'bar': ['3'], 'baz': ['2'], 'qux': ['1']}
        self._test_attr_info(attr_info, expect_val)

        attr_info = {'foo': {'is_filter': True}, 'bar': {'is_filter': True},
                     'baz': {'is_filter': True}, 'qux': {'is_filter': True},
                     'quz': {'is_filter': False}}
        expect_val = {'foo': ['4'], 'bar': ['3'], 'baz': ['2'], 'qux': ['1']}
        self._test_attr_info(attr_info, expect_val)

    def _test_attr_info(self, attr_info, expect_val=None):
        path = '/?foo=4&bar=3&baz=2&qux=1'
        request = webob.Request.blank(path)
        if expect_val:
            actual_val = api_common.get_filters(
                request, attr_info,
                is_filter_validation_supported=True)
            self.assertEqual(expect_val, actual_val)
        else:
            self.assertRaises(
                exc.HTTPBadRequest, api_common.get_filters, request, attr_info,
                is_filter_validation_supported=True)

    def test_attr_info_without_conversion(self):
        path = '/?foo=4&bar=3&baz=2&qux=1'
        request = webob.Request.blank(path)
        attr_info = {'foo': {'key': 'val'}}
        expect_val = {'foo': ['4'], 'bar': ['3'], 'baz': ['2'], 'qux': ['1']}
        actual_val = api_common.get_filters(request, attr_info)
        self.assertEqual(expect_val, actual_val)

    def test_attr_info_with_convert_list_to(self):
        path = '/?foo=key=4&bar=3&foo=key=2&qux=1'
        request = webob.Request.blank(path)
        attr_info = {
            'foo': {
                'convert_list_to': converters.convert_kvp_list_to_dict,
            }
        }
        expect_val = {'foo': {'key': ['2', '4']}, 'bar': ['3'], 'qux': ['1']}
        actual_val = api_common.get_filters(request, attr_info)
        self.assertOrderedEqual(expect_val, actual_val)

    def test_attr_info_with_convert_to(self):
        path = '/?foo=4&bar=3&baz=2&qux=1'
        request = webob.Request.blank(path)
        attr_info = {'foo': {'convert_to': converters.convert_to_int}}
        expect_val = {'foo': [4], 'bar': ['3'], 'baz': ['2'], 'qux': ['1']}
        actual_val = api_common.get_filters(request, attr_info)
        self.assertEqual(expect_val, actual_val)

    def test_attr_info_with_base_db_attributes(self):
        path = '/?__contains__=1&__class__=2'
        request = webob.Request.blank(path)
        self.assertEqual({}, api_common.get_filters(request, {}))


class CreateResourceTestCase(base.BaseTestCase):
    def test_resource_creation(self):
        resource = v2_base.create_resource('fakes', 'fake', None, {})
        self.assertIsInstance(resource, webob.dec.wsgify)


class ResourceExtendedActionsTestCase(base.BaseTestCase):
    def test_resource_attrs_included(self):
        resource = v2_base.create_resource(
            l3_ext_gw_multihoming.COLLECTION_NAME,
            l3_ext_gw_multihoming.RESOURCE_NAME,
            mock.Mock(),
            l3.RESOURCE_ATTRIBUTE_MAP[l3.ROUTERS],
            member_actions=l3.ACTION_MAP[l3.ROUTER])

        action = 'update_external_gateways'
        router_id = uuidutils.generate_uuid()
        url = (l3_ext_gw_multihoming.RESOURCE_NAME + '/' + router_id + '/' +
               action)
        request = api_resource.Request.blank(url, method='PUT')
        controller = resource.controller
        method = getattr(controller, action)

        _router = {
            'router': {'external_gateways': [
                {'network_id': 'net_uuid', 'qos_policy_id': 'qos_uuid'}]
            }
        }
        _args = {'body': _router,
                 'id': router_id
                 }
        resource = {'id': router_id}
        with mock.patch.object(controller, '_item', return_value=resource), \
                mock.patch.object(policy, 'enforce') as mock_enforce:
            method(request=request, **_args)
            resource.update({'network_id': 'net_uuid',
                             'qos_policy_id': 'qos_uuid'})
            mock_enforce.assert_called_once_with(
                request.context,
                action,
                resource,
                pluralized=l3_ext_gw_multihoming.COLLECTION_NAME
            )

    def test_resource_attrs_not_included(self):
        resource = v2_base.create_resource(
            address_group.COLLECTION_NAME,
            address_group.RESOURCE_NAME,
            mock.Mock(),
            address_group.RESOURCE_ATTRIBUTE_MAP[
                address_group.COLLECTION_NAME],
            member_actions=address_group.ACTION_MAP[
                address_group.RESOURCE_NAME])

        action = 'add_addresses'
        ag_id = uuidutils.generate_uuid()
        url = (address_group.RESOURCE_NAME + '/' + ag_id + '/' +
               action)
        request = api_resource.Request.blank(url, method='PUT')
        controller = resource.controller
        method = getattr(controller, action)

        _args = {'body': {'addresses': ['10.10.0.0/24']},
                 'id': ag_id
                 }
        resource = {'id': ag_id}
        with mock.patch.object(controller, '_item', return_value=resource), \
                mock.patch.object(policy, 'enforce') as mock_enforce:
            method(request=request, **_args)
            mock_enforce.assert_called_once_with(
                request.context,
                action,
                resource,
                pluralized=address_group.COLLECTION_NAME
            )
