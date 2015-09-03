# Copyright 2012 OpenStack Foundation
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

from oslo_middleware import request_id
import webob

from neutron import auth
from neutron.tests import base


class NeutronKeystoneContextTestCase(base.BaseTestCase):
    def setUp(self):
        super(NeutronKeystoneContextTestCase, self).setUp()

        @webob.dec.wsgify
        def fake_app(req):
            self.context = req.environ['neutron.context']
            return webob.Response()

        self.context = None
        self.middleware = auth.NeutronKeystoneContext(fake_app)
        self.request = webob.Request.blank('/')
        self.request.headers['X_AUTH_TOKEN'] = 'testauthtoken'

    def test_no_user_id(self):
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '401 Unauthorized')

    def test_with_user_id(self):
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.user_id, 'testuserid')
        self.assertEqual(self.context.user, 'testuserid')

    def test_with_tenant_id(self):
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'test_user_id'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.tenant_id, 'testtenantid')
        self.assertEqual(self.context.tenant, 'testtenantid')

    def test_roles_no_admin(self):
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        self.request.headers['X_ROLES'] = 'role1, role2 , role3,role4,role5'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.roles, ['role1', 'role2', 'role3',
                                              'role4', 'role5'])
        self.assertEqual(self.context.is_admin, False)

    def test_roles_with_admin(self):
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        self.request.headers['X_ROLES'] = ('role1, role2 , role3,role4,role5,'
                                           'AdMiN')
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.roles, ['role1', 'role2', 'role3',
                                              'role4', 'role5', 'AdMiN'])
        self.assertEqual(self.context.is_admin, True)

    def test_with_user_tenant_name(self):
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        self.request.headers['X_PROJECT_NAME'] = 'testtenantname'
        self.request.headers['X_USER_NAME'] = 'testusername'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.user_id, 'testuserid')
        self.assertEqual(self.context.user_name, 'testusername')
        self.assertEqual(self.context.tenant_id, 'testtenantid')
        self.assertEqual(self.context.tenant_name, 'testtenantname')

    def test_request_id_extracted_from_env(self):
        req_id = 'dummy-request-id'
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        self.request.environ[request_id.ENV_REQUEST_ID] = req_id
        self.request.get_response(self.middleware)
        self.assertEqual(req_id, self.context.request_id)

    def test_with_auth_token(self):
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.auth_token, 'testauthtoken')

    def test_without_auth_token(self):
        self.request.headers['X_PROJECT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        del self.request.headers['X_AUTH_TOKEN']
        self.request.get_response(self.middleware)
        self.assertIsNone(self.context.auth_token)
