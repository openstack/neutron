# Copyright (c) 2015 Mirantis, Inc.
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

from collections import namedtuple
import mock
from oslo_config import cfg
from oslo_policy import policy as oslo_policy
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import pecan
from pecan import request
from pecan import set_config
from pecan.testing import load_test_app
import testtools

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron import context
from neutron import manager
from neutron.pecan_wsgi.controllers import root as controllers
from neutron import policy
from neutron.tests.unit import testlib_api

_SERVICE_PLUGIN_RESOURCE = 'serviceplugin'
_SERVICE_PLUGIN_COLLECTION = _SERVICE_PLUGIN_RESOURCE + 's'
_SERVICE_PLUGIN_INDEX_BODY = {_SERVICE_PLUGIN_COLLECTION: []}


class FakeServicePluginController(object):
    resource = _SERVICE_PLUGIN_RESOURCE

    @pecan.expose(generic=True,
                  content_type='application/json',
                  template='json')
    def index(self):
        return _SERVICE_PLUGIN_INDEX_BODY


class PecanFunctionalTest(testlib_api.SqlTestCase):

    def setUp(self):
        self.setup_coreplugin('neutron.plugins.ml2.plugin.Ml2Plugin')
        super(PecanFunctionalTest, self).setUp()
        self.addCleanup(extensions.PluginAwareExtensionManager.clear_instance)
        self.addCleanup(set_config, {}, overwrite=True)
        self.set_config_overrides()
        self.setup_app()
        self.setup_service_plugin()

    def setup_app(self):
        self.app = load_test_app(os.path.join(
            os.path.dirname(__file__),
            'config.py'
        ))
        self._gen_port()

    def _gen_port(self):
        pl = manager.NeutronManager.get_plugin()
        network_id = pl.create_network(context.get_admin_context(), {
            'network':
            {'name': 'pecannet', 'tenant_id': 'tenid', 'shared': False,
             'admin_state_up': True, 'status': 'ACTIVE'}})['id']
        self.port = pl.create_port(context.get_admin_context(), {
            'port':
            {'tenant_id': 'tenid', 'network_id': network_id,
             'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
             'mac_address': '00:11:22:33:44:55',
             'admin_state_up': True, 'device_id': 'FF',
             'device_owner': 'pecan', 'name': 'pecan'}})

    def set_config_overrides(self):
        cfg.CONF.set_override('auth_strategy', 'noauth')

    def setup_service_plugin(self):
        manager.NeutronManager.set_controller_for_resource(
            _SERVICE_PLUGIN_COLLECTION, FakeServicePluginController())


class TestV2Controller(PecanFunctionalTest):

    def test_get(self):
        response = self.app.get('/v2.0/ports.json')
        self.assertEqual(response.status_int, 200)

    def test_post(self):
        response = self.app.post_json('/v2.0/ports.json',
            params={'port': {'network_id': self.port['network_id'],
                             'admin_state_up': True,
                             'tenant_id': 'tenid'}},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 201)

    def test_put(self):
        response = self.app.put_json('/v2.0/ports/%s.json' % self.port['id'],
                                     params={'port': {'name': 'test'}},
                                     headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 200)

    def test_delete(self):
        response = self.app.delete('/v2.0/ports/%s.json' % self.port['id'],
                                   headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 204)

    def test_plugin_initialized(self):
        self.assertIsNotNone(manager.NeutronManager._instance)

    def test_get_extensions(self):
        response = self.app.get('/v2.0/extensions.json')
        self.assertEqual(response.status_int, 200)

    def test_get_specific_extension(self):
        response = self.app.get('/v2.0/extensions/allowed-address-pairs.json')
        self.assertEqual(response.status_int, 200)

    def test_service_plugin_uri(self):
        service_plugin = namedtuple('DummyServicePlugin', 'path_prefix')
        service_plugin.path_prefix = 'dummy'
        nm = manager.NeutronManager.get_instance()
        nm.service_plugins['dummy_sp'] = service_plugin
        response = self.app.get('/v2.0/dummy/serviceplugins.json')
        self.assertEqual(200, response.status_int)
        self.assertEqual(_SERVICE_PLUGIN_INDEX_BODY, response.json_body)


class TestErrors(PecanFunctionalTest):

    def test_404(self):
        response = self.app.get('/assert_called_once', expect_errors=True)
        self.assertEqual(response.status_int, 404)

    def test_bad_method(self):
        response = self.app.patch('/v2.0/ports/44.json',
                                  expect_errors=True)
        self.assertEqual(response.status_int, 405)


class TestRequestID(PecanFunctionalTest):

    def test_request_id(self):
        response = self.app.get('/')
        self.assertIn('x-openstack-request-id', response.headers)
        self.assertTrue(
            response.headers['x-openstack-request-id'].startswith('req-'))
        id_part = response.headers['x-openstack-request-id'].split('req-')[1]
        self.assertTrue(uuidutils.is_uuid_like(id_part))


class TestKeystoneAuth(PecanFunctionalTest):

    def set_config_overrides(self):
        # default auth strategy is keystone so we pass
        pass

    def test_auth_enforced(self):
        response = self.app.get('/', expect_errors=True)
        self.assertEqual(response.status_int, 401)


class TestInvalidAuth(PecanFunctionalTest):
    def setup_app(self):
        # disable normal app setup since it will fail
        pass

    def test_invalid_auth_strategy(self):
        cfg.CONF.set_override('auth_strategy', 'badvalue')
        with testtools.ExpectedException(n_exc.InvalidConfigurationOption):
            load_test_app(os.path.join(os.path.dirname(__file__), 'config.py'))


class TestExceptionTranslationHook(PecanFunctionalTest):

    def test_neutron_nonfound_to_webob_exception(self):
        # this endpoint raises a Neutron notfound exception. make sure it gets
        # translated into a 404 error
        with mock.patch(
            'neutron.pecan_wsgi.controllers.root.CollectionsController.get',
            side_effect=n_exc.NotFound()
        ):
            response = self.app.get('/v2.0/ports.json', expect_errors=True)
            self.assertEqual(response.status_int, 404)

    def test_unexpected_exception(self):
        with mock.patch(
            'neutron.pecan_wsgi.controllers.root.CollectionsController.get',
            side_effect=ValueError('secretpassword')
        ):
            response = self.app.get('/v2.0/ports.json', expect_errors=True)
            self.assertNotIn(response.body, 'secretpassword')
            self.assertEqual(response.status_int, 500)


class TestRequestProcessing(PecanFunctionalTest):

    def setUp(self):
        super(TestRequestProcessing, self).setUp()

        # request.context is thread-local storage so it has to be accessed by
        # the controller. We can capture it into a list here to assert on after
        # the request finishes.

        def capture_request_details(*args, **kwargs):
            self.captured_context = request.context

        mock.patch('neutron.pecan_wsgi.controllers.root.'
                   'CollectionsController.get',
                   side_effect=capture_request_details).start()
        mock.patch('neutron.pecan_wsgi.controllers.root.'
                   'CollectionsController.create',
                   side_effect=capture_request_details).start()
        mock.patch('neutron.pecan_wsgi.controllers.root.ItemController.get',
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
            '/v2.0/ports.json',
            params={'port': {'network_id': self.port['network_id'],
                             'name': 'the_port',
                             'admin_state_up': True}},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual('port', self.captured_context['resource'])
        self.assertEqual('ports', self.captured_context['collection'])
        resources = self.captured_context['resources']
        self.assertEqual(1, len(resources))
        self.assertEqual(self.port['network_id'],
                         resources[0]['network_id'])
        self.assertEqual('the_port', resources[0]['name'])

    def test_resource_processing_post_bulk(self):
        self.app.post_json(
            '/v2.0/ports.json',
            params={'ports': [{'network_id': self.port['network_id'],
                               'name': 'the_port_1',
                               'admin_state_up': True},
                              {'network_id': self.port['network_id'],
                               'name': 'the_port_2',
                               'admin_state_up': True}]},
            headers={'X-Project-Id': 'tenid'})
        resources = self.captured_context['resources']
        self.assertEqual(2, len(resources))
        self.assertEqual(self.port['network_id'],
                         resources[0]['network_id'])
        self.assertEqual('the_port_1', resources[0]['name'])
        self.assertEqual(self.port['network_id'],
                         resources[1]['network_id'])
        self.assertEqual('the_port_2', resources[1]['name'])

    def test_resource_processing_post_unknown_attribute_returns_400(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
            params={'port': {'network_id': self.port['network_id'],
                             'name': 'the_port',
                             'alien': 'E.T.',
                             'admin_state_up': True}},
            headers={'X-Project-Id': 'tenid'},
            expect_errors=True)
        self.assertEqual(400, response.status_int)

    def test_resource_processing_post_validation_errori_returns_400(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
            params={'port': {'network_id': self.port['network_id'],
                             'name': 'the_port',
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
            manager.NeutronManager.get_service_plugins()['L3_ROUTER_NAT'],
            self.req_stash['plugin'])


class TestEnforcementHooks(PecanFunctionalTest):

    def test_network_ownership_check(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
            params={'port': {'network_id': self.port['network_id'],
                             'admin_state_up': True}},
            headers={'X-Project-Id': 'tenid'})
        self.assertEqual(201, response.status_int)

    def test_quota_enforcement(self):
        # TODO(kevinbenton): this test should do something
        pass


class TestPolicyEnforcementHook(PecanFunctionalTest):

    FAKE_RESOURCE = {
        'mehs': {
            'id': {'allow_post': False, 'allow_put': False,
                   'is_visible': True, 'primary_key': True},
            'attr': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': ''},
            'restricted_attr': {'allow_post': True, 'allow_put': True,
                                'is_visible': True, 'default': ''},
            'tenant_id': {'allow_post': True, 'allow_put': False,
                          'required_by_policy': True,
                          'validate': {'type:string':
                                       attributes.TENANT_ID_MAX_LEN},
                          'is_visible': True}
        }
    }

    def setUp(self):
        # Create a controller for a fake resource. This will make the tests
        # independent from the evolution of the API (so if one changes the API
        # or the default policies there won't be any risk of breaking these
        # tests, or at least I hope so)
        super(TestPolicyEnforcementHook, self).setUp()
        self.mock_plugin = mock.Mock()
        attributes.RESOURCE_ATTRIBUTE_MAP.update(self.FAKE_RESOURCE)
        attributes.PLURALS['mehs'] = 'meh'
        manager.NeutronManager.set_plugin_for_resource('meh', self.mock_plugin)
        fake_controller = controllers.CollectionsController('mehs', 'meh')
        manager.NeutronManager.set_controller_for_resource(
            'mehs', fake_controller)
        # Inject policies for the fake resource
        policy.init()
        policy._ENFORCER.set_rules(
            oslo_policy.Rules.from_dict(
                {'create_meh': '',
                 'update_meh': 'rule:admin_only',
                 'delete_meh': 'rule:admin_only',
                 'get_meh': 'rule:admin_only or field:mehs:id=xxx',
                 'get_meh:restricted_attr': 'rule:admin_only'}),
            overwrite=False)

    def test_before_on_create_authorized(self):
        # Mock a return value for an hypothetical create operation
        self.mock_plugin.create_meh.return_value = {
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        response = self.app.post_json('/v2.0/mehs.json',
                                      params={'meh': {'attr': 'meh'}},
                                      headers={'X-Project-Id': 'tenid'})
        # We expect this operation to succeed
        self.assertEqual(201, response.status_int)
        self.assertEqual(0, self.mock_plugin.get_meh.call_count)
        self.assertEqual(1, self.mock_plugin.create_meh.call_count)

    def test_before_on_put_not_authorized(self):
        # The policy hook here should load the resource, and therefore we must
        # mock a get response
        self.mock_plugin.get_meh.return_value = {
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        # The policy engine should trigger an exception in 'before', and the
        # plugin method should not be called at all
        response = self.app.put_json('/v2.0/mehs/xxx.json',
                                     params={'meh': {'attr': 'meh'}},
                                     headers={'X-Project-Id': 'tenid'},
                                     expect_errors=True)
        self.assertEqual(403, response.status_int)
        self.assertEqual(1, self.mock_plugin.get_meh.call_count)
        self.assertEqual(0, self.mock_plugin.update_meh.call_count)

    def test_before_on_delete_not_authorized(self):
        # The policy hook here should load the resource, and therefore we must
        # mock a get response
        self.mock_plugin.delete_meh.return_value = None
        self.mock_plugin.get_meh.return_value = {
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        # The policy engine should trigger an exception in 'before', and the
        # plugin method should not be called
        response = self.app.delete_json('/v2.0/mehs/xxx.json',
                                        headers={'X-Project-Id': 'tenid'},
                                        expect_errors=True)
        self.assertEqual(403, response.status_int)
        self.assertEqual(1, self.mock_plugin.get_meh.call_count)
        self.assertEqual(0, self.mock_plugin.delete_meh.call_count)

    def test_after_on_get_not_authorized(self):
        # The GET test policy will deny access to anything whose id is not
        # 'xxx', so the following request should be forbidden
        self.mock_plugin.get_meh.return_value = {
            'id': 'yyy',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        # The policy engine should trigger an exception in 'after', and the
        # plugin method should be called
        response = self.app.get('/v2.0/mehs/yyy.json',
                                headers={'X-Project-Id': 'tenid'},
                                expect_errors=True)
        self.assertEqual(403, response.status_int)
        self.assertEqual(1, self.mock_plugin.get_meh.call_count)

    def test_after_on_get_excludes_admin_attribute(self):
        self.mock_plugin.get_meh.return_value = {
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}
        response = self.app.get('/v2.0/mehs/xxx.json',
                                headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, response.status_int)
        json_response = jsonutils.loads(response.body)
        self.assertNotIn('restricted_attr', json_response['meh'])

    def test_after_on_list_excludes_admin_attribute(self):
        self.mock_plugin.get_mehs.return_value = [{
            'id': 'xxx',
            'attr': 'meh',
            'restricted_attr': '',
            'tenant_id': 'tenid'}]
        response = self.app.get('/v2.0/mehs',
                                headers={'X-Project-Id': 'tenid'})
        self.assertEqual(200, response.status_int)
        json_response = jsonutils.loads(response.body)
        self.assertNotIn('restricted_attr', json_response['mehs'][0])


class TestRootController(PecanFunctionalTest):
    """Test version listing on root URI."""

    def test_get(self):
        response = self.app.get('/')
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        versions = json_body.get('versions')
        self.assertEqual(1, len(versions))
        for (attr, value) in controllers.V2Controller.version_info.items():
            self.assertIn(attr, versions[0])
            self.assertEqual(value, versions[0][attr])

    def _test_method_returns_405(self, method):
        api_method = getattr(self.app, method)
        response = api_method('/', expect_errors=True)
        self.assertEqual(response.status_int, 405)

    def test_post(self):
        self._test_method_returns_405('post')

    def test_put(self):
        self._test_method_returns_405('put')

    def test_patch(self):
        self._test_method_returns_405('patch')

    def test_delete(self):
        self._test_method_returns_405('delete')

    def test_head(self):
        self._test_method_returns_405('head')


class TestQuotasController(TestRootController):
    """Test quota management API controller."""

    base_url = '/v2.0/quotas'
    default_expected_limits = {
        'network': 10,
        'port': 50,
        'subnet': 10}

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
        # As DELETE does not return a body we need another GET
        response = self.app.get(url, headers={'X-Project-Id': 'foo'})
        self.assertEqual(200, response.status_int)
        json_body = jsonutils.loads(response.body)
        self._verify_default_limits(json_body)

    def test_delete(self):
        # TODO(salv-orlando)
        pass
