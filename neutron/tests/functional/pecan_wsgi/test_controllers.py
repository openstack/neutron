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

from collections import namedtuple

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
import pecan
from pecan import request

from neutron.api.v2 import attributes
from neutron import context
from neutron import manager
from neutron.pecan_wsgi.controllers import root as controllers
from neutron.plugins.common import constants
from neutron.tests.functional.pecan_wsgi import test_functional

_SERVICE_PLUGIN_RESOURCE = 'serviceplugin'
_SERVICE_PLUGIN_COLLECTION = _SERVICE_PLUGIN_RESOURCE + 's'
_SERVICE_PLUGIN_INDEX_BODY = {_SERVICE_PLUGIN_COLLECTION: []}


class FakeServicePluginController(object):
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

    def setup_service_plugin(self):
        manager.NeutronManager.set_controller_for_resource(
            _SERVICE_PLUGIN_COLLECTION, FakeServicePluginController())

    def _test_method_returns_405(self, method):
        api_method = getattr(self.app, method)
        response = api_method(self.base_url, expect_errors=True)
        self.assertEqual(response.status_int, 405)

    def test_get(self):
        response = self.app.get(self.base_url)
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        versions = json_body.get('versions')
        self.assertEqual(1, len(versions))
        for (attr, value) in controllers.V2Controller.version_info.items():
            self.assertIn(attr, versions[0])
            self.assertEqual(value, versions[0][attr])

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


class TestV2Controller(TestRootController):

    base_url = '/v2.0'

    def test_get(self):
        """Verify current version info are returned."""
        response = self.app.get(self.base_url)
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        self.assertEqual('v2.0', json_body['version']['id'])
        self.assertEqual('CURRENT', json_body['version']['status'])

    def test_routing_successs(self):
        """Test dispatch to controller for existing resource."""
        response = self.app.get('%s/ports.json' % self.base_url)
        self.assertEqual(response.status_int, 200)

    def test_routing_failure(self):
        """Test dispatch to controller for non-existing resource."""
        response = self.app.get('%s/idonotexist.json' % self.base_url,
                                expect_errors=True)
        self.assertEqual(response.status_int, 404)


class TestExtensionsController(TestRootController):
    """Test extension listing and detail reporting."""

    base_url = '/v2.0/extensions'

    def _get_supported_extensions(self):
        supported_extensions = set()
        for plugin in manager.NeutronManager.get_service_plugins().values():
            supported_extensions |= set(plugin.supported_extension_aliases)
        return supported_extensions

    def test_index(self):
        response = self.app.get(self.base_url)
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        returned_aliases = [ext['alias'] for ext in json_body['extensions']]
        # FIXME(salv-orlando): workaround for issue concerning rbac-policies
        # not showing up in supported_extension_aliases
        try:
            returned_aliases.remove('rbac-policies')
        except ValueError:
            # The extension was not loaded, do not bother
            pass
        supported_extensions = self._get_supported_extensions()
        self.assertEqual(supported_extensions, set(returned_aliases))

    def test_get(self):
        # Fetch any extension supported by plugins
        test_alias = self._get_supported_extensions().pop()
        response = self.app.get('%s/%s' % (self.base_url, test_alias))
        self.assertEqual(response.status_int, 200)
        json_body = jsonutils.loads(response.body)
        self.assertEqual(test_alias, json_body['extension']['alias'])


class TestQuotasController(test_functional.PecanFunctionalTest):
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


class TestResourceController(TestRootController):
    """Test generic controller"""
    # TODO(salv-orlando): This test case must not explicitly test the 'port'
    # resource. Also it should validate correct plugin/resource association

    def setUp(self):
        super(TestResourceController, self).setUp()
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

    def test_get(self):
        response = self.app.get('/v2.0/ports.json')
        self.assertEqual(response.status_int, 200)

    def test_post(self):
        response = self.app.post_json(
            '/v2.0/ports.json',
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
        json_body = jsonutils.loads(response.body)
        self.assertEqual(1, len(json_body))
        self.assertIn('port', json_body)
        self.assertEqual('test', json_body['port']['name'])
        self.assertEqual('tenid', json_body['port']['tenant_id'])

    def test_delete(self):
        response = self.app.delete('/v2.0/ports/%s.json' % self.port['id'],
                                   headers={'X-Project-Id': 'tenid'})
        self.assertEqual(response.status_int, 204)

    def test_plugin_initialized(self):
        self.assertIsNotNone(manager.NeutronManager._instance)


class TestRequestProcessing(TestResourceController):

    def setUp(self):
        super(TestRequestProcessing, self).setUp()

        # request.context is thread-local storage so it has to be accessed by
        # the controller. We can capture it into a list here to assert on after
        # the request finishes.

        def capture_request_details(*args, **kwargs):
            self.captured_context = request.context

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

    def test_service_plugin_uri(self):
        service_plugin = namedtuple('DummyServicePlugin', 'path_prefix')
        service_plugin.path_prefix = 'dummy'
        nm = manager.NeutronManager.get_instance()
        nm.service_plugins['dummy_sp'] = service_plugin
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
            ['neutron.services.l3_router.l3_router_plugin.L3RouterPlugin'])

        super(TestRouterController, self).setUp()

        # Create a network, a subnet, and a router
        pl = manager.NeutronManager.get_plugin()
        service_plugins = manager.NeutronManager.get_service_plugins()
        l3_plugin = service_plugins[constants.L3_ROUTER_NAT]
        ctx = context.get_admin_context()
        network_id = pl.create_network(
            ctx,
            {'network':
             {'name': 'pecannet',
              'tenant_id': 'tenid',
              'shared': False,
              'admin_state_up': True,
              'status': 'ACTIVE'}})['id']
        self.subnet = pl.create_subnet(
            ctx,
            {'subnet':
             {'tenant_id': 'tenid',
              'network_id': network_id,
              'name': 'pecansub',
              'ip_version': 4,
              'cidr': '10.20.30.0/24',
              'gateway_ip': '10.20.30.1',
              'enable_dhcp': True,
              'allocation_pools': [
                  {'start': '10.20.30.2',
                   'end': '10.20.30.254'}],
              'dns_nameservers': [],
              'host_routes': []}})
        self.router = l3_plugin.create_router(
            ctx,
            {'router':
             {'name': 'pecanrtr',
              'tenant_id': 'tenid',
              'admin_state_up': True}})

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
