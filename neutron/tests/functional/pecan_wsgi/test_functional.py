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

import mock
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants
from oslo_config import cfg
from oslo_middleware import base
from oslo_service import wsgi
from oslo_utils import uuidutils
import testtools
import webob.dec
import webtest

from neutron.api import extensions as exts
from neutron import manager
from neutron import tests
from neutron.tests.unit import testlib_api


class InjectContext(base.ConfigurableMiddleware):

    @webob.dec.wsgify
    def __call__(self, req):
        user_id = req.headers.get('X_USER_ID', '')

        # Determine the tenant
        tenant_id = req.headers.get('X_PROJECT_ID')

        # Suck out the roles
        roles = [r.strip() for r in req.headers.get('X_ROLES', '').split(',')]

        # Human-friendly names
        tenant_name = req.headers.get('X_PROJECT_NAME')
        user_name = req.headers.get('X_USER_NAME')

        # Create a context with the authentication data
        ctx = context.Context(user_id, tenant_id, roles=roles,
                              user_name=user_name, tenant_name=tenant_name)
        req.environ['neutron.context'] = ctx
        return self.application


def create_test_app():
    paste_config_loc = os.path.join(os.path.dirname(tests.__file__), 'etc',
                                    'api-paste.ini')
    paste_config_loc = os.path.abspath(paste_config_loc)
    cfg.CONF.set_override('api_paste_config', paste_config_loc)
    loader = wsgi.Loader(cfg.CONF)
    app = loader.load_app('neutron')
    app = InjectContext(app)
    return webtest.TestApp(app)


class PecanFunctionalTest(testlib_api.SqlTestCase):

    def setUp(self, service_plugins=None, extensions=None):
        self.setup_coreplugin('ml2', load_plugins=False)
        super(PecanFunctionalTest, self).setUp()
        self.addCleanup(exts.PluginAwareExtensionManager.clear_instance)
        self.set_config_overrides()
        manager.init()
        ext_mgr = exts.PluginAwareExtensionManager.get_instance()
        if extensions:
            ext_mgr.extensions = extensions
        if service_plugins:
            service_plugins[constants.CORE] = ext_mgr.plugins.get(
                constants.CORE)
            ext_mgr.plugins = service_plugins
        self.app = create_test_app()

    def set_config_overrides(self):
        cfg.CONF.set_override('auth_strategy', 'noauth')

    def do_request(self, url, tenant_id=None, admin=False,
                   expect_errors=False):
        if admin:
            if not tenant_id:
                tenant_id = 'admin'
            headers = {'X-Tenant-Id': tenant_id,
                       'X-Roles': 'admin'}
        else:
            headers = {'X-Tenant-ID': tenant_id or ''}
        return self.app.get(url, headers=headers, expect_errors=expect_errors)


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
        response = self.app.get('/v2.0/')
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
        response = self.app.get('/v2.0/', expect_errors=True)
        self.assertEqual(response.status_int, 401)


class TestInvalidAuth(PecanFunctionalTest):
    def setup_app(self):
        # disable normal app setup since it will fail
        pass

    def test_invalid_auth_strategy(self):
        cfg.CONF.set_override('auth_strategy', 'badvalue')
        # NOTE(blogan): the auth.pipeline_factory will throw a KeyError
        # with a bad value because that value is not the paste config.
        # This KeyError is translated to a LookupError, which the oslo wsgi
        # code translates into PasteAppNotFound.
        with testtools.ExpectedException(wsgi.PasteAppNotFound):
            create_test_app()


class TestExceptionTranslationHook(PecanFunctionalTest):

    def test_neutron_nonfound_to_webob_exception(self):
        # this endpoint raises a Neutron notfound exception. make sure it gets
        # translated into a 404 error
        with mock.patch(
            'neutron.pecan_wsgi.controllers.resource.'
            'CollectionsController.get',
            side_effect=n_exc.NotFound()
        ):
            response = self.app.get('/v2.0/ports.json', expect_errors=True)
            self.assertEqual(response.status_int, 404)

    def test_unexpected_exception(self):
        with mock.patch(
            'neutron.pecan_wsgi.controllers.resource.'
            'CollectionsController.get',
            side_effect=ValueError('secretpassword')
        ):
            response = self.app.get('/v2.0/ports.json', expect_errors=True)
            self.assertNotIn(response.body, 'secretpassword')
            self.assertEqual(response.status_int, 500)
