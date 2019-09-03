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

import mock
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_policy import policy as oslo_policy
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import pecan
from pecan import request

from neutron.api import extensions
from neutron.conf import quota as qconf
from neutron import manager
from neutron.pecan_wsgi.controllers import root as controllers
from neutron.pecan_wsgi.controllers import utils as controller_utils
from neutron import policy
from neutron.tests.common import helpers
from neutron.tests.functional.pecan_wsgi import test_functional
from neutron.tests.functional.pecan_wsgi import utils as pecan_utils
from neutron.tests.unit import dummy_plugin


_SERVICE_PLUGIN_RESOURCE = 'serviceplugin'
_SERVICE_PLUGIN_COLLECTION = _SERVICE_PLUGIN_RESOURCE + 's'
_SERVICE_PLUGIN_INDEX_BODY = {_SERVICE_PLUGIN_COLLECTION: []}


class FakeServicePluginController(controller_utils.NeutronPecanController):
    resource = _SERVICE_PLUGIN_RESOURCE
    collection = _SERVICE_PLUGIN_COLLECTION

    @pecan.expose(generic=True,
                  content_type='application/json',
                  template='json')
    def index(self):
        return _SERVICE_PLUGIN_INDEX_BODY


class TestRootController(test_functional.PecanFunctionalTest):
    """Test version listing on root URI."""

    base_url = '/'

    def setUp(self):
        super(TestRootController, self).setUp()
        self.setup_service_plugin()
        self.plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()

    def setup_service_plugin(self):
        manager.NeutronManager.set_controller_for_resource(
            _SERVICE_PLUGIN_COLLECTION,
            FakeServicePluginController(_SERVICE_PLUGIN_COLLECTION,
                                        _SERVICE_PLUGIN_RESOURCE,
                                        resource_info={'foo': {}}))

    def _test_method_returns_code(self, method, code=200):
        api_method = getattr(self.app, method)
        response = api_method(self.base_url, expect_errors=True)
        self.assertEqual(response.status_int, code)

    def test_get(self):
        response = self.app.get(self.base_url)
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        versions = json_body.get('versions')
        self.assertEqual(1, len(versions))
        for (attr, value) in controllers.V2Controller.version_info.items():
            self.assertIn(attr, versions[0])
            self.assertEqual(value, versions[0][attr])

    def test_methods(self):
        self._test_method_returns_code('post', 405)
        self._test_method_returns_code('patch', 405)
        self._test_method_returns_code('delete', 405)
        self._test_method_returns_code('head', 405)
        self._test_method_returns_code('put', 405)


class TestV2Controller(TestRootController):

    base_url = '/v2.0/'

    def test_get(self):
        """Verify current version info are returned."""
        response = self.app.get(self.base_url)
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        self.assertIn('resources', json_body)
        self.assertIsInstance(json_body['resources'], list)
        for r in json_body['resources']:
            self.assertIn("links", r)
            self.assertIn("name", r)
            self.assertIn("collection", r)
            self.assertIn(self.base_url, r['links'][0]['href'])

    def test_get_no_trailing_slash(self):
        response = self.app.get(self.base_url[:-1], expect_errors=True)
        self.assertEqual(response.status_int, 404)

    def test_routing_successs(self):
        """Test dispatch to controller for existing resource."""
        response = self.app.get('%sports.json' % self.base_url)
        self.assertEqual(response.status_int, 200)

    def test_routing_failure(self):
        """Test dispatch to controller for non-existing resource."""
        response = self.app.get('%sidonotexist.json' % self.base_url,
                                expect_errors=True)
        self.assertEqual(response.status_int, 404)

    def test_methods(self):
        self._test_method_returns_code('post', 405)
        self._test_method_returns_code('put', 405)
        self._test_method_returns_code('patch', 405)
        self._test_method_returns_code('delete', 405)
        self._test_method_returns_code('head', 405)
        self._test_method_returns_code('delete', 405)


class TestExtensionsController(TestRootController):
    """Test extension listing and detail reporting."""

    base_url = '/v2.0/extensions'

    def _get_supported_extensions(self):
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        return ext_mgr.get_supported_extension_aliases()

    def test_index(self):
        response = self.app.get(self.base_url)
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        returned_aliases = [ext['alias'] for ext in json_body['extensions']]
        supported_extensions = self._get_supported_extensions()
        self.assertEqual(supported_extensions, set(returned_aliases))

    def test_get(self):
        # Fetch any extension supported by plugins
        test_alias = self._get_supported_extensions().pop()
        response = self.app.get('%s/%s' % (self.base_url, test_alias))
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        self.assertEqual(test_alias, json_body['extension']['alias'])

    def test_methods(self):
        self._test_method_returns_code('post', 404)
        self._test_method_returns_code('put', 404)
        self._test_method_returns_code('patch', 404)
        self._test_method_returns_code('delete', 404)
        self._test_method_returns_code('head', 404)
        self._test_method_returns_code('delete', 404)


class TestQuotasController(test_functional.PecanFunctionalTest):
    """Test quota management API controller."""

    base_url = '/v2.0/quotas'
    default_expected_limits = {
        'network': qconf.DEFAULT_QUOTA_NETWORK,
        'port': qconf.DEFAULT_QUOTA_PORT,
        'subnet': qconf.DEFAULT_QUOTA_SUBNET}

    def _verify_limits(self, response, limits):
        for resource, limit in limits.items():
            self.assertEqual(limit, response['quota'][resource])

    def _verify_default_limits(self, response):
        self._verify_limits(response, self.default_expected_limits)

    def _verify_after_update(self, response, updated_limits):
        expected_limits = self.default_expected_limits.copy()
        expected_limits.update(updated_limits)
        self._verify_limits(response, expected_limits)

    def test_index_admin(self):
        # NOTE(salv-orlando): The quota controller has an hardcoded check for
        # admin-ness for this operation, which is supposed to return quotas for
        # all tenants. Such check is "vestigial" from the home-grown WSGI and
        # shall be removed
        response = self.app.get('%s.json' % self.base_url,
                                headers={'X-Project-Id': 'admin',
                                         'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)

    def test_index(self):
        response = self.app.get('%s.json' % self.base_url, expect_errors=True)
        self.assertEqual(403, response.status_int)

    def test_get_admin(self):
        response = self.app.get('%s/foo.json' % self.base_url,
                                headers={'X-Project-Id': 'admin',
                                         'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)
        # As quota limits have not been updated, expect default values
        json_body = jsonutils.loads(response.body)
        self._verify_default_limits(json_body)

    def test_get(self):
        # It is not ok to access another tenant's limits
        url = '%s/foo.json' % self.base_url
        response = self.app.get(url, expect_errors=True)
        self.assertEqual(403, response.status_int)
        # It is however ok to retrieve your own limits
        response = self.app.get(url, headers={'X-Project-Id': 'foo'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        self._verify_default_limits(json_body)

    def test_put_get_delete(self):
        # PUT and DELETE actions are in the same test as a meaningful DELETE
        # test would require a put anyway
        url = '%s/foo.json' % self.base_url
        response = self.app.put_json(url,
                                     params={'quota': {'network': 99}},
                                     headers={'X-Project-Id': 'admin',
                                              'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        self._verify_after_update(json_body, {'network': 99})

        response = self.app.get(url, headers={'X-Project-Id': 'foo'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        self._verify_after_update(json_body, {'network': 99})

        response = self.app.delete(url, headers={'X-Project-Id': 'admin',
                                                 'X-Roles': 'admin'})
        self.assertEqual(204, response.status_int)
        self.assertFalse(response.body)
        # As DELETE does not return a body we need another GET
        response = self.app.get(url, headers={'X-Project-Id': 'foo'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        self._verify_default_limits(json_body)

    def test_update_list_delete(self):
        # PUT and DELETE actions are in the same test as a meaningful DELETE
        # test would require a put anyway
        url = '%s/foo.json' % self.base_url
        response = self.app.put_json(url,
                                     params={'quota': {'network': 99}},
                                     headers={'X-Project-Id': 'admin',
                                              'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        self._verify_after_update(json_body, {'network': 99})

        response = self.app.get(self.base_url,
                                headers={'X-Project-Id': 'admin',
                                         'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        found = False
        for qs in json_body['quotas']:
            if qs['tenant_id'] == 'foo':
                found = True
        self.assertTrue(found)

        response = self.app.delete(url, headers={'X-Project-Id': 'admin',
                                                 'X-Roles': 'admin'})
        self.assertEqual(204, response.status_int)
        self.assertFalse(response.body)
        response = self.app.get(self.base_url,
                                headers={'X-Project-Id': 'admin',
                                         'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        for qs in json_body['quotas']:
            self.assertNotEqual('foo', qs['tenant_id'])

    def test_quotas_get_defaults(self):
        response = self.app.get('%s/foo/default.json' % self.base_url,
                                headers={'X-Project-Id': 'admin',
                                         'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)
        # As quota limits have not been updated, expect default values
        json_body = jsonutils.loads(response.body)
        self._verify_default_limits(json_body)

    def test_get_tenant_info(self):
        response = self.app.get('%s/tenant.json' % self.base_url,
                                headers={'X-Project-Id': 'admin',
                                         'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        self.assertEqual('admin', json_body['tenant']['tenant_id'])


class TestResourceController(TestRootController):
    """Test generic controller"""
    # TODO(salv-orlando): This test case must not explicitly test the 'port'
    # resource. Also it should validate correct plugin/resource association
    base_url = '/v2.0'

    def setUp(self):
        super(TestResourceController, self).setUp()
        policy.init()
        self.addCleanup(policy.reset)
        self._gen_port()

    def _gen_port(self):
        network_id = self.plugin.create_network(context.get_admin_context(), {
            'network':
            {'name': 'pecannet', 'tenant_id': 'tenid', 'shared': False,
             'admin_state_up': True, 'status': 'ACTIVE'}})['id']
        self.port = self.plugin.create_port(context.get_admin_context(), {
            'port':
            {'tenant_id': 'tenid', 'network_id': network_id,
             'fixed_ips': n_const.ATTR_NOT_SPECIFIED,
             'mac_address': '00:11:22:33:44:55',
             'admin_state_up': True, 'device_id': 'FF',
             'device_owner': 'pecan', 'name': 'pecan'}})

    def test_get(self):
        response = self.app.get('/v2.0/ports.json')
        self.assertEqual(response.status_int, 200)

    def _check_item(self, expected, item):
        for attribute in expected:
            self.assertIn(attribute, item)
        self.assertEqual(len(expected), len(item))

    def _test_get_collection_with_fields_selector(self, fields=None):
        fields = fields or []
        query_params = ['fields=%s' % field for field in fields]
        url = '/v2.0/ports.json'
        if query_params:
            url = '%s?%s' % (url, '&'.join(query_params))
        list_resp = self.app.get(url, headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, list_resp.status_int)
        for item in jsonutils.loads(list_resp.body).get('ports', []):
            for field in fields:
                self.assertIn(field, item)
            if fields:
                self.assertEqual(len(fields), len(item))
            else:
                for field in ('id', 'name', 'device_owner'):
                    self.assertIn(field, item)

    def test_get_collection_with_multiple_fields_selector(self):
        self._test_get_collection_with_fields_selector(fields=['id', 'name'])

    def test_get_collection_with_single_fields_selector(self):
        self._test_get_collection_with_fields_selector(fields=['name'])

    def test_get_collection_without_fields_selector(self):
        self._test_get_collection_with_fields_selector(fields=[])

    def test_project_id_in_mandatory_fields(self):
        # ports only specifies that tenant_id is mandatory, but project_id
        # should still be passed to the plugin.
        mock_get = mock.patch.object(self.plugin, 'get_ports',
                                     return_value=[]).start()
        self.app.get(
            '/v2.0/ports.json?fields=id',
            headers={'X-Project-Id': 'tenid'}
        )
        self.assertIn('project_id', mock_get.mock_calls[-1][2]['fields'])

    def test_get_item_with_fields_selector(self):
        item_resp = self.app.get(
            '/v2.0/ports/%s.json?fields=id&fields=name' % self.port['id'],
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, item_resp.status_int)
        self._check_item(['id', 'name'],
                         jsonutils.loads(item_resp.body)['port'])
        # Explicitly require an attribute which is also 'required_by_policy'.
        # The attribute should not be stripped while generating the response
        item_resp = self.app.get(
            '/v2.0/ports/%s.json?fields=id&fields=tenant_id' % self.port['id'],
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, item_resp.status_int)
        self._check_item(['id', 'tenant_id'],
                         jsonutils.loads(item_resp.body)['port'])

    def test_duped_and_empty_fields_stripped(self):
        mock_get = mock.patch.object(self.plugin, 'get_ports',
                                     return_value=[]).start()
        self.app.get(
            '/v2.0/ports.json?fields=id&fields=name&fields=&fields=name',
            headers={'X-Project-Id': 'tenid'}
        )
        received = mock_get.mock_calls[-1][2]['fields']
        self.assertNotIn('', received)
        self.assertEqual(len(received), len(set(received)))

    def test_post(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
            params={'port': {'network_id': self.port['network_id'],
                             'admin_state_up': True,
                             'tenant_id': 'tenid'}},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 201)

    def test_post_with_retry(self):
        self._create_failed = False
        orig = self.plugin.create_port

        def new_create(*args, **kwargs):
            if not self._create_failed:
                self._create_failed = True
                raise db_exc.RetryRequest(ValueError())
            return orig(*args, **kwargs)

        with mock.patch.object(self.plugin, 'create_port',
                               new=new_create):
            response = self.app.post_json(
                '/v2.0/ports.json',
                params={'port': {'network_id': self.port['network_id'],
                                 'admin_state_up': True,
                                 'tenant_id': 'tenid'}},
                headers={'X-Project-Id': 'tenid'})
            self.assertEqual(201, response.status_int)

    def test_put(self):
        response = self.app.put_json('/v2.0/ports/%s.json' % self.port['id'],
                                     params={'port': {'name': 'test'}},
                                     headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        self.assertEqual(1, len(json_body))
        self.assertIn('port', json_body)
        self.assertEqual('test', json_body['port']['name'])
        self.assertEqual('tenid', json_body['port']['tenant_id'])

    def test_delete(self):
        response = self.app.delete('/v2.0/ports/%s.json' % self.port['id'],
                                   headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 204)
        self.assertFalse(response.body)

    def test_delete_disallows_body(self):
        response = self.app.delete_json(
            '/v2.0/ports/%s.json' % self.port['id'],
            params={'port': {'name': 'test'}},
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(response.status_int, 400)

    def test_plugin_initialized(self):
        self.assertIsNotNone(manager.NeutronManager._instance)

    def test_methods(self):
        self._test_method_returns_code('post', 405)
        self._test_method_returns_code('put', 405)
        self._test_method_returns_code('patch', 405)
        self._test_method_returns_code('delete', 405)
        self._test_method_returns_code('head', 405)
        self._test_method_returns_code('delete', 405)

    def test_post_with_empty_body(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
            headers={'X-Project-Id': 'tenid'},
            params={},
            expect_errors=True)
        self.assertEqual(response.status_int, 400)

    def test_post_with_unsupported_json_type(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
            headers={'X-Project-Id': 'tenid'},
            params=[1, 2, 3],
            expect_errors=True)
        self.assertEqual(response.status_int, 400)

    def test_bulk_create(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
            params={'ports': [{'network_id': self.port['network_id'],
                             'admin_state_up': True,
                             'tenant_id': 'tenid'},
                             {'network_id': self.port['network_id'],
                              'admin_state_up': True,
                              'tenant_id': 'tenid'}]
                    },
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(201, response.status_int)
        json_body = jsonutils.loads(response.body)
        self.assertIn('ports', json_body)
        ports = json_body['ports']
        self.assertEqual(2, len(ports))
        for port in ports:
            self.assertEqual(1, len(port['security_groups']))

    def test_bulk_create_with_sg(self):
        sg_response = self.app.post_json(
                '/v2.0/security-groups.json',
                params={'security_group': {
                    "name": "functest",
                    "description": "Functional test"}},
                headers={'X-Project-Id': 'tenid'})
        self.assertEqual(201, sg_response.status_int)
        sg_json_body = jsonutils.loads(sg_response.body)
        self.assertIn('security_group', sg_json_body)
        sg_id = sg_json_body['security_group']['id']

        port_response = self.app.post_json(
                '/v2.0/ports.json',
                params={'ports': [{'network_id': self.port['network_id'],
                                 'admin_state_up': True,
                                 'security_groups': [sg_id],
                                 'tenant_id': 'tenid'},
                                 {'network_id': self.port['network_id'],
                                  'admin_state_up': True,
                                 'security_groups': [sg_id],
                                  'tenant_id': 'tenid'}]
                        },
                headers={'X-Project-Id': 'tenid'})
        self.assertEqual(201, port_response.status_int)
        json_body = jsonutils.loads(port_response.body)
        self.assertIn('ports', json_body)
        ports = json_body['ports']
        self.assertEqual(2, len(ports))
        for port in ports:
            self.assertEqual(1, len(port['security_groups']))

    def test_emulated_bulk_create(self):
        self.plugin._FORCE_EMULATED_BULK = True
        response = self.app.post_json(
            '/v2.0/ports.json',
            params={'ports': [{'network_id': self.port['network_id'],
                             'admin_state_up': True,
                             'tenant_id': 'tenid'},
                             {'network_id': self.port['network_id'],
                              'admin_state_up': True,
                              'tenant_id': 'tenid'}]
                    },
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 201)
        json_body = jsonutils.loads(response.body)
        self.assertIn('ports', json_body)
        self.assertEqual(2, len(json_body['ports']))

    def test_emulated_bulk_create_rollback(self):
        self.plugin._FORCE_EMULATED_BULK = True
        response = self.app.post_json(
            '/v2.0/ports.json',
            params={'ports': [{'network_id': self.port['network_id'],
                             'admin_state_up': True,
                             'tenant_id': 'tenid'},
                             {'network_id': self.port['network_id'],
                              'admin_state_up': True,
                              'tenant_id': 'tenid'},
                             {'network_id': 'bad_net_id',
                              'admin_state_up': True,
                              'tenant_id': 'tenid'}]
                    },
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(response.status_int, 400)
        response = self.app.get(
            '/v2.0/ports.json',
            headers={'X-Project-Id': 'tenid'})
        # all ports should be rolled back from above so we are just left
        # with the one created in setup
        self.assertEqual(1, len(jsonutils.loads(response.body)['ports']))

    def test_bulk_create_one_item(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
            params={'ports': [{'network_id': self.port['network_id'],
                               'admin_state_up': True,
                               'tenant_id': 'tenid'}]
                    },
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 201)
        json_body = jsonutils.loads(response.body)
        self.assertIn('ports', json_body)
        self.assertEqual(1, len(json_body['ports']))


class TestPaginationAndSorting(test_functional.PecanFunctionalTest):

    RESOURCE_COUNT = 6

    def setUp(self):
        super(TestPaginationAndSorting, self).setUp()
        policy.init()
        self.addCleanup(policy.reset)
        self.plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()
        self._create_networks(self.RESOURCE_COUNT)
        self.networks = self._get_collection()['networks']

    def _create_networks(self, count=1):
        network_ids = []
        for index in range(count):
            network = {'name': 'pecannet-%d' % index, 'tenant_id': 'tenid',
                       'shared': False, 'admin_state_up': True,
                       'status': 'ACTIVE'}
            network_id = self.plugin.create_network(
                self.ctx, {'network': network})['id']
            network_ids.append(network_id)
        return network_ids

    def _get_collection(self, collection=None, limit=None, marker=None,
                        fields=None, page_reverse=False, sort_key=None,
                        sort_dir=None):
        collection = collection or 'networks'
        fields = fields or []
        query_params = []
        if limit:
            query_params.append('limit=%d' % limit)
        if marker:
            query_params.append('marker=%s' % marker)
        if page_reverse:
            query_params.append('page_reverse=True')
        if sort_key:
            query_params.append('sort_key=%s' % sort_key)
        if sort_dir:
            query_params.append('sort_dir=%s' % sort_dir)
        query_params.extend(['%s%s' % ('fields=', field) for field in fields])
        url = '/v2.0/%s.json' % collection
        if query_params:
            url = '%s?%s' % (url, '&'.join(query_params))
        list_resp = self.app.get(url, headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, list_resp.status_int)
        return list_resp.json

    def _test_get_collection_with_pagination(self, expected_list,
                                             collection=None,
                                             limit=None, marker=None,
                                             fields=None, page_reverse=False,
                                             sort_key=None, sort_dir=None):
        expected_list = expected_list or []
        collection = collection or 'networks'
        list_resp = self._get_collection(collection=collection, limit=limit,
                                         marker=marker, fields=fields,
                                         page_reverse=page_reverse,
                                         sort_key=sort_key, sort_dir=sort_dir)
        if limit and marker:
            links_key = '%s_links' % collection
            self.assertIn(links_key, list_resp)
        if not fields or 'id' in fields:
            list_resp_ids = [item['id'] for item in list_resp[collection]]
            self.assertEqual(expected_list, list_resp_ids)
        if fields:
            for item in list_resp[collection]:
                for field in fields:
                    self.assertIn(field, item)

    def test_get_collection_with_pagination_limit(self):
        self._test_get_collection_with_pagination([self.networks[0]['id']],
                                                  limit=1)

    def test_get_collection_with_pagination_fields_no_pk(self):
        self._test_get_collection_with_pagination([self.networks[0]['id']],
                                                  limit=1, fields=['name'])

    def test_get_collection_with_pagination_limit_over_count(self):
        expected_ids = [network['id'] for network in self.networks]
        self._test_get_collection_with_pagination(
            expected_ids, limit=self.RESOURCE_COUNT + 1)

    def test_get_collection_with_pagination_marker(self):
        marker = self.networks[2]['id']
        expected_ids = [network['id'] for network in self.networks[3:]]
        self._test_get_collection_with_pagination(expected_ids, limit=3,
                                                  marker=marker)

    def test_get_collection_with_pagination_marker_without_limit(self):
        marker = self.networks[2]['id']
        expected_ids = [network['id'] for network in self.networks]
        self._test_get_collection_with_pagination(expected_ids, marker=marker)

    def test_get_collection_with_pagination_and_fields(self):
        expected_ids = [network['id'] for network in self.networks[:2]]
        self._test_get_collection_with_pagination(
            expected_ids, limit=2, fields=['id', 'name'])

    def test_get_collection_with_pagination_page_reverse(self):
        marker = self.networks[2]['id']
        expected_ids = [network['id'] for network in self.networks[:2]]
        self._test_get_collection_with_pagination(expected_ids, limit=3,
                                                  marker=marker,
                                                  page_reverse=True)

    def test_get_collection_with_sorting_desc(self):
        nets = sorted(self.networks, key=lambda net: net['name'], reverse=True)
        expected_ids = [network['id'] for network in nets]
        self._test_get_collection_with_pagination(expected_ids,
                                                  sort_key='name',
                                                  sort_dir='desc')

    def test_get_collection_with_sorting_asc(self):
        nets = sorted(self.networks, key=lambda net: net['name'])
        expected_ids = [network['id'] for network in nets]
        self._test_get_collection_with_pagination(expected_ids,
                                                  sort_key='name',
                                                  sort_dir='asc')


class TestRequestProcessing(TestRootController):

    def setUp(self):
        super(TestRequestProcessing, self).setUp()
        mock.patch('neutron.pecan_wsgi.hooks.notifier.registry').start()
        # request.context is thread-local storage so it has to be accessed by
        # the controller. We can capture it into a list here to assert on after
        # the request finishes.

        def capture_request_details(*args, **kwargs):
            self.captured_context = request.context
            self.request_params = kwargs

        mock.patch('neutron.pecan_wsgi.controllers.resource.'
                   'CollectionsController.get',
                   side_effect=capture_request_details).start()
        mock.patch('neutron.pecan_wsgi.controllers.resource.'
                   'CollectionsController.create',
                   side_effect=capture_request_details).start()
        mock.patch('neutron.pecan_wsgi.controllers.resource.'
                   'ItemController.get',
                   side_effect=capture_request_details).start()
    # TODO(kevinbenton): add context tests for X-Roles etc

    def test_context_set_in_request(self):
        self.app.get('/v2.0/ports.json',
                     headers={'X-Project-Id': 'tenant_id'})
        self.assertEqual('tenant_id',
                         self.captured_context['neutron_context'].tenant_id)

    def test_core_resource_identified(self):
        self.app.get('/v2.0/ports.json')
        self.assertEqual('port', self.captured_context['resource'])
        self.assertEqual('ports', self.captured_context['collection'])

    def test_lookup_identifies_resource_id(self):
        # We now this will return a 404 but that's not the point as it is
        # mocked
        self.app.get('/v2.0/ports/reina.json')
        self.assertEqual('port', self.captured_context['resource'])
        self.assertEqual('ports', self.captured_context['collection'])
        self.assertEqual('reina', self.captured_context['resource_id'])

    def test_resource_processing_post(self):
        self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'the_net',
                                'admin_state_up': True}},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual('network', self.captured_context['resource'])
        self.assertEqual('networks', self.captured_context['collection'])
        resources = self.captured_context['resources']
        is_bulk = self.captured_context['is_bulk']
        self.assertEqual(1, len(resources))
        self.assertEqual('the_net', resources[0]['name'])
        self.assertTrue(resources[0]['admin_state_up'])
        self.assertFalse(is_bulk)

    def test_resource_processing_post_bulk(self):
        self.app.post_json(
            '/v2.0/networks.json',
            params={'networks': [{'name': 'the_net_1',
                                  'admin_state_up': True},
                                 {'name': 'the_net_2',
                                  'admin_state_up': False}]},
            headers={'X-Project-Id': 'tenid'})
        resources = self.captured_context['resources']
        is_bulk = self.captured_context['is_bulk']
        self.assertEqual(2, len(resources))
        self.assertTrue(resources[0]['admin_state_up'])
        self.assertEqual('the_net_1', resources[0]['name'])
        self.assertFalse(resources[1]['admin_state_up'])
        self.assertEqual('the_net_2', resources[1]['name'])
        self.assertTrue(is_bulk)

    def test_resource_processing_post_bulk_one_item(self):
        self.app.post_json(
            '/v2.0/networks.json',
            params={'networks': [{'name': 'the_net_1',
                                  'admin_state_up': True}]},
            headers={'X-Project-Id': 'tenid'})
        resources = self.captured_context['resources']
        is_bulk = self.captured_context['is_bulk']
        self.assertEqual(1, len(resources))
        self.assertTrue(is_bulk)

    def test_resource_processing_post_unknown_attribute_returns_400(self):
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'the_net',
                                'alien': 'E.T.',
                                'admin_state_up': True}},
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(400, response.status_int)

    def test_resource_processing_post_validation_error_returns_400(self):
        response = self.app.post_json(
            '/v2.0/networks.json',
            params={'network': {'name': 'the_net',
                                'admin_state_up': 'invalid_value'}},
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(400, response.status_int)

    def test_service_plugin_identified(self):
        # TODO(kevinbenton): fix the unit test setup to include an l3 plugin
        self.skipTest("A dummy l3 plugin needs to be setup")
        self.app.get('/v2.0/routers.json')
        self.assertEqual('router', self.req_stash['resource_type'])
        # make sure the core plugin was identified as the handler for ports
        self.assertEqual(
            directory.get_plugin(plugin_constants.L3),
            self.req_stash['plugin'])

    def test_service_plugin_uri(self):
        nm = manager.NeutronManager.get_instance()
        nm.path_prefix_resource_mappings[dummy_plugin.RESOURCE_NAME] = [
            _SERVICE_PLUGIN_COLLECTION]
        response = self.do_request('/v2.0/dummy/serviceplugins.json')
        self.assertEqual(200, response.status_int)
        self.assertEqual(_SERVICE_PLUGIN_INDEX_BODY, response.json_body)


class TestRouterController(TestResourceController):
    """Specialized tests for the router resource controller

    This test class adds tests specific for the router controller in
    order to verify the 'member_action' functionality, which this
    controller uses for adding and removing router interfaces.
    """

    def setUp(self):
        cfg.CONF.set_override(
            'service_plugins',
            ['neutron.services.l3_router.l3_router_plugin.L3RouterPlugin',
             'neutron.services.flavors.flavors_plugin.FlavorsPlugin'])
        super(TestRouterController, self).setUp()
        policy.init()
        self.addCleanup(policy.reset)
        plugin = directory.get_plugin()
        ctx = context.get_admin_context()
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        network_id = pecan_utils.create_network(ctx, plugin)['id']
        self.subnet = pecan_utils.create_subnet(ctx, plugin, network_id)
        self.router = pecan_utils.create_router(ctx, l3_plugin)

    def test_member_actions_processing(self):
        response = self.app.put_json(
            '/v2.0/routers/%s/add_router_interface.json' % self.router['id'],
            params={'subnet_id': self.subnet['id']},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, response.status_int)

    def test_non_existing_member_action_returns_404(self):
        response = self.app.put_json(
            '/v2.0/routers/%s/do_meh.json' % self.router['id'],
            params={'subnet_id': 'doesitevenmatter'},
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(404, response.status_int)

    def test_unsupported_method_member_action(self):
        response = self.app.post_json(
            '/v2.0/routers/%s/add_router_interface.json' % self.router['id'],
            params={'subnet_id': self.subnet['id']},
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(405, response.status_int)

        response = self.app.get(
            '/v2.0/routers/%s/add_router_interface.json' % self.router['id'],
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(405, response.status_int)


class TestDHCPAgentShimControllers(test_functional.PecanFunctionalTest):

    def setUp(self):
        super(TestDHCPAgentShimControllers, self).setUp()
        policy.init()
        policy._ENFORCER.set_rules(
            oslo_policy.Rules.from_dict(
                {'get_dhcp-agents': 'role:admin',
                 'get_dhcp-networks': 'role:admin',
                 'create_dhcp-networks': 'role:admin',
                 'delete_dhcp-networks': 'role:admin'}),
            overwrite=False)
        plugin = directory.get_plugin()
        ctx = context.get_admin_context()
        self.network = pecan_utils.create_network(ctx, plugin)
        self.agent = helpers.register_dhcp_agent()
        # NOTE(blogan): Not sending notifications because this test is for
        # testing the shim controllers
        plugin.agent_notifiers[n_const.AGENT_TYPE_DHCP] = None

    def test_list_dhcp_agents_hosting_network(self):
        response = self.app.get(
            '/v2.0/networks/%s/dhcp-agents.json' % self.network['id'],
            headers={'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)

    def test_list_networks_on_dhcp_agent(self):
        response = self.app.get(
            '/v2.0/agents/%s/dhcp-networks.json' % self.agent.id,
            headers={'X-Project-Id': 'tenid', 'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)

    def test_add_remove_dhcp_agent(self):
        headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        self.app.post_json(
            '/v2.0/agents/%s/dhcp-networks.json' % self.agent.id,
            headers=headers, params={'network_id': self.network['id']})
        response = self.app.get(
            '/v2.0/networks/%s/dhcp-agents.json' % self.network['id'],
            headers=headers)
        self.assertIn(self.agent.id,
                      [a['id'] for a in response.json['agents']])
        self.app.delete('/v2.0/agents/%(a)s/dhcp-networks/%(n)s.json' % {
            'a': self.agent.id, 'n': self.network['id']}, headers=headers)
        response = self.app.get(
            '/v2.0/networks/%s/dhcp-agents.json' % self.network['id'],
            headers=headers)
        self.assertNotIn(self.agent.id,
                         [a['id'] for a in response.json['agents']])


class TestL3AgentShimControllers(test_functional.PecanFunctionalTest):

    def setUp(self):
        cfg.CONF.set_override(
            'service_plugins',
            ['neutron.services.l3_router.l3_router_plugin.L3RouterPlugin',
             'neutron.services.flavors.flavors_plugin.FlavorsPlugin'])
        super(TestL3AgentShimControllers, self).setUp()
        policy.init()
        policy._ENFORCER.set_rules(
            oslo_policy.Rules.from_dict(
                {'get_l3-agents': 'role:admin',
                 'get_l3-routers': 'role:admin'}),
            overwrite=False)
        ctx = context.get_admin_context()
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.router = pecan_utils.create_router(ctx, l3_plugin)
        self.agent = helpers.register_l3_agent()
        # NOTE(blogan): Not sending notifications because this test is for
        # testing the shim controllers
        l3_plugin.agent_notifiers[n_const.AGENT_TYPE_L3] = None

    def test_list_l3_agents_hosting_router(self):
        response = self.app.get(
            '/v2.0/routers/%s/l3-agents.json' % self.router['id'],
            headers={'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)

    def test_list_routers_on_l3_agent(self):
        response = self.app.get(
            '/v2.0/agents/%s/l3-routers.json' % self.agent.id,
            headers={'X-Roles': 'admin'})
        self.assertEqual(200, response.status_int)

    def test_add_remove_l3_agent(self):
        headers = {'X-Project-Id': 'tenid', 'X-Roles': 'admin'}
        response = self.app.post_json(
            '/v2.0/agents/%s/l3-routers.json' % self.agent.id,
            headers=headers, params={'router_id': self.router['id']})
        self.assertEqual(201, response.status_int)
        response = self.app.get(
            '/v2.0/routers/%s/l3-agents.json' % self.router['id'],
            headers=headers)
        self.assertIn(self.agent.id,
                      [a['id'] for a in response.json['agents']])
        response = self.app.delete(
            '/v2.0/agents/%(a)s/l3-routers/%(n)s.json' % {
                'a': self.agent.id, 'n': self.router['id']}, headers=headers)
        self.assertEqual(204, response.status_int)
        self.assertFalse(response.body)
        response = self.app.get(
            '/v2.0/routers/%s/l3-agents.json' % self.router['id'],
            headers=headers)
        self.assertNotIn(self.agent.id,
                         [a['id'] for a in response.json['agents']])


class TestShimControllers(test_functional.PecanFunctionalTest):

    def setUp(self):
        fake_ext = pecan_utils.FakeExtension()
        fake_plugin = pecan_utils.FakePlugin()
        plugins = {pecan_utils.FakePlugin.PLUGIN_TYPE: fake_plugin}
        new_extensions = {fake_ext.get_alias(): fake_ext}
        super(TestShimControllers, self).setUp(
            service_plugins=plugins, extensions=new_extensions)
        policy.init()
        policy._ENFORCER.set_rules(
            oslo_policy.Rules.from_dict(
                {'get_meh_meh': '',
                 'get_meh_mehs': '',
                 'get_fake_subresources': ''}),
            overwrite=False)
        self.addCleanup(policy.reset)

    def test_hyphenated_resource_controller_not_shimmed(self):
        collection = pecan_utils.FakeExtension.HYPHENATED_COLLECTION.replace(
            '_', '-')
        resource = pecan_utils.FakeExtension.HYPHENATED_RESOURCE
        url = '/v2.0/{}/something.json'.format(collection)
        resp = self.app.get(url)
        self.assertEqual(200, resp.status_int)
        self.assertEqual({resource: {'fake': 'something'}}, resp.json)

    def test_hyphenated_collection_controller_not_shimmed(self):
        body_collection = pecan_utils.FakeExtension.HYPHENATED_COLLECTION
        uri_collection = body_collection.replace('_', '-')
        url = '/v2.0/{}.json'.format(uri_collection)
        resp = self.app.get(url)
        self.assertEqual(200, resp.status_int)
        self.assertEqual({body_collection: [{'fake': 'fake'}]}, resp.json)

    def test_hyphenated_collection_subresource_controller_not_shimmed(self):
        body_collection = pecan_utils.FakeExtension.HYPHENATED_COLLECTION
        uri_collection = body_collection.replace('_', '-')
        # there is only one subresource so far
        sub_resource_collection = (
            pecan_utils.FakeExtension.FAKE_SUB_RESOURCE_COLLECTION)
        temp_id = uuidutils.generate_uuid()
        url = '/v2.0/{0}/{1}/{2}'.format(
            uri_collection,
            temp_id,
            sub_resource_collection.replace('_', '-'))
        resp = self.app.get(url)
        self.assertEqual(200, resp.status_int)
        self.assertEqual({sub_resource_collection: {'foo': temp_id}},
                         resp.json)


class TestMemberActionController(test_functional.PecanFunctionalTest):
    def setUp(self):
        fake_ext = pecan_utils.FakeExtension()
        fake_plugin = pecan_utils.FakePlugin()
        plugins = {pecan_utils.FakePlugin.PLUGIN_TYPE: fake_plugin}
        new_extensions = {fake_ext.get_alias(): fake_ext}
        super(TestMemberActionController, self).setUp(
            service_plugins=plugins, extensions=new_extensions)
        hyphen_collection = pecan_utils.FakeExtension.HYPHENATED_COLLECTION
        self.collection = hyphen_collection.replace('_', '-')

    def test_get_member_action_controller(self):
        url = '/v2.0/{}/something/boo_meh.json'.format(self.collection)
        resp = self.app.get(url)
        self.assertEqual(200, resp.status_int)
        self.assertEqual({'boo_yah': 'something'}, resp.json)

    def test_put_member_action_controller(self):
        url = '/v2.0/{}/something/put_meh.json'.format(self.collection)
        resp = self.app.put_json(url, params={'it_matters_not': 'ok'})
        self.assertEqual(200, resp.status_int)
        self.assertEqual({'poo_yah': 'something'}, resp.json)

    def test_get_member_action_does_not_exist(self):
        url = '/v2.0/{}/something/are_you_still_there.json'.format(
            self.collection)
        resp = self.app.get(url, expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_put_member_action_does_not_exist(self):
        url = '/v2.0/{}/something/are_you_still_there.json'.format(
            self.collection)
        resp = self.app.put_json(url, params={'it_matters_not': 'ok'},
                                 expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_put_on_get_member_action(self):
        url = '/v2.0/{}/something/boo_meh.json'.format(self.collection)
        resp = self.app.put_json(url, params={'it_matters_not': 'ok'},
                                 expect_errors=True)
        self.assertEqual(405, resp.status_int)

    def test_get_on_put_member_action(self):
        url = '/v2.0/{}/something/put_meh.json'.format(self.collection)
        resp = self.app.get(url, expect_errors=True)
        self.assertEqual(405, resp.status_int)


class TestParentSubresourceController(test_functional.PecanFunctionalTest):
    def setUp(self):
        fake_ext = pecan_utils.FakeExtension()
        fake_plugin = pecan_utils.FakePlugin()
        plugins = {pecan_utils.FakePlugin.PLUGIN_TYPE: fake_plugin}
        new_extensions = {fake_ext.get_alias(): fake_ext}
        super(TestParentSubresourceController, self).setUp(
            service_plugins=plugins, extensions=new_extensions)
        policy.init()
        policy._ENFORCER.set_rules(
            oslo_policy.Rules.from_dict(
                {'get_fake_duplicate': '',
                 'get_meh_meh_fake_duplicate': ''}),
            overwrite=False)
        self.addCleanup(policy.reset)
        hyphen_collection = pecan_utils.FakeExtension.HYPHENATED_COLLECTION
        self.collection = hyphen_collection.replace('_', '-')
        self.fake_collection = (pecan_utils.FakeExtension.
                                FAKE_PARENT_SUBRESOURCE_COLLECTION)

    def test_get_duplicate_parent_resource(self):
        url = '/v2.0/{}'.format(self.fake_collection)
        resp = self.app.get(url)
        self.assertEqual(200, resp.status_int)
        self.assertEqual({'fake_duplicates': [{'fake': 'fakeduplicates'}]},
                         resp.json)

    def test_get_duplicate_parent_resource_item(self):
        url = '/v2.0/{}/something'.format(self.fake_collection)
        resp = self.app.get(url)
        self.assertEqual(200, resp.status_int)
        self.assertEqual({'fake_duplicate': {'fake': 'something'}}, resp.json)

    def test_get_parent_resource_and_duplicate_subresources(self):
        url = '/v2.0/{0}/something/{1}'.format(self.collection,
                                               self.fake_collection)
        resp = self.app.get(url)
        self.assertEqual(200, resp.status_int)
        self.assertEqual({'fake_duplicates': [{'fake': 'something'}]},
                         resp.json)

    def test_get_child_resource_policy_check(self):
        policy.reset()
        policy.init()
        policy._ENFORCER.set_rules(
            oslo_policy.Rules.from_dict(
                {'get_meh_meh_fake_duplicate': ''}
            )
        )
        url = '/v2.0/{0}/something/{1}'.format(self.collection,
                                               self.fake_collection)
        resp = self.app.get(url)
        self.assertEqual(200, resp.status_int)
        self.assertEqual({'fake_duplicates': [{'fake': 'something'}]},
                         resp.json)


class TestExcludeAttributePolicy(test_functional.PecanFunctionalTest):

    def setUp(self):
        super(TestExcludeAttributePolicy, self).setUp()
        policy.init()
        self.addCleanup(policy.reset)
        plugin = directory.get_plugin()
        ctx = context.get_admin_context()
        self.network_id = pecan_utils.create_network(ctx, plugin)['id']
        mock.patch('neutron.pecan_wsgi.controllers.resource.'
                   'CollectionsController.get').start()

    def test_get_networks(self):
        response = self.app.get('/v2.0/networks/%s.json' % self.network_id,
                headers={'X-Project-Id': 'tenid'})
        json_body = jsonutils.loads(response.body)
        self.assertEqual(response.status_int, 200)
        self.assertEqual('tenid', json_body['network']['project_id'])
        self.assertEqual('tenid', json_body['network']['tenant_id'])
