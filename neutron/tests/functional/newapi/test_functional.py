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
from oslo_config import cfg
from oslo_utils import uuidutils
from pecan import request
from pecan import set_config
from pecan.testing import load_test_app
import testtools

from neutron.common import exceptions as n_exc
from neutron import manager
from neutron.tests.unit import testlib_api


class PecanFunctionalTest(testlib_api.SqlTestCase):

    def setUp(self):
        self.setup_coreplugin('neutron.plugins.ml2.plugin.Ml2Plugin')
        super(PecanFunctionalTest, self).setUp()
        self.addCleanup(set_config, {}, overwrite=True)
        self.set_config_overrides()
        self.setup_app()

    def setup_app(self):
        self.app = load_test_app(os.path.join(
            os.path.dirname(__file__),
            'config.py'
        ))

    def set_config_overrides(self):
        cfg.CONF.set_override('auth_strategy', 'noauth')


class TestV2Controller(PecanFunctionalTest):

    def test_get(self):
        response = self.app.get('/v2.0/ports.json')
        self.assertEqual(response.status_int, 200)

    def test_post(self):
        response = self.app.post_json('/v2.0/ports.json',
                                      params={'port': {'name': 'test'}})
        self.assertEqual(response.status_int, 200)

    def test_put(self):
        response = self.app.put_json('/v2.0/ports/44.json',
                                     params={'port': {'name': 'test'}})
        self.assertEqual(response.status_int, 200)

    def test_delete(self):
        response = self.app.delete('/v2.0/ports/44.json')
        self.assertEqual(response.status_int, 200)

    def test_plugin_initialized(self):
        self.assertIsNotNone(manager.NeutronManager._instance)


class TestErrors(PecanFunctionalTest):

    def test_404(self):
        response = self.app.get('/assert_called_once', expect_errors=True)
        self.assertEqual(response.status_int, 404)

    def test_bad_method(self):
        response = self.app.patch('/v2.0/',
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
                'neutron.newapi.controllers.root.GeneralController.get',
                side_effect=n_exc.NotFound()):
            response = self.app.get('/v2.0/ports.json', expect_errors=True)
            self.assertEqual(response.status_int, 404)

    def test_unexpected_exception(self):
        with mock.patch(
                'neutron.newapi.controllers.root.GeneralController.get',
                side_effect=ValueError('secretpassword')):
            response = self.app.get('/v2.0/ports.json', expect_errors=True)
            self.assertNotIn(response.body, 'secretpassword')
            self.assertEqual(response.status_int, 500)


class TestContextHook(PecanFunctionalTest):

    # TODO(kevinbenton): add tests for X-Roles etc

    def test_context_set_in_request(self):
        request_stash = []
        # request.context is thread-local storage so it has to be accessed by
        # the controller. We can capture it into a list here to assert on after
        # the request finishes.
        with mock.patch(
            'neutron.newapi.controllers.root.GeneralController.get',
            side_effect=lambda *x, **y: request_stash.append(request.context)
        ):
            self.app.get('/v2.0/ports.json',
                         headers={'X-Tenant-Id': 'tenant_id'})
            self.assertEqual('tenant_id', request_stash[0].tenant_id)
