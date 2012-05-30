import unittest

import webob

from quantum import auth


class QuantumKeystoneContextTestCase(unittest.TestCase):
    def setUp(self):
        super(QuantumKeystoneContextTestCase, self).setUp()

        @webob.dec.wsgify
        def fake_app(req):
            self.context = req.environ['quantum.context']
            return webob.Response()

        self.context = None
        self.middleware = auth.QuantumKeystoneContext(fake_app)
        self.request = webob.Request.blank('/')
        self.request.headers['X_AUTH_TOKEN'] = 'testauthtoken'

    def test_no_user_no_user_id(self):
        self.request.headers['X_TENANT_ID'] = 'testtenantid'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '401 Unauthorized')

    def test_with_user(self):
        self.request.headers['X_TENANT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.user_id, 'testuserid')

    def test_with_user_id(self):
        self.request.headers['X_TENANT_ID'] = 'testtenantid'
        self.request.headers['X_USER'] = 'testuser'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.user_id, 'testuser')

    def test_user_id_trumps_user(self):
        self.request.headers['X_TENANT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        self.request.headers['X_USER'] = 'testuser'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.user_id, 'testuserid')

    def test_with_tenant_id(self):
        self.request.headers['X_TENANT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'test_user_id'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.tenant_id, 'testtenantid')

    def test_with_tenant(self):
        self.request.headers['X_TENANT'] = 'testtenant'
        self.request.headers['X_USER_ID'] = 'test_user_id'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.tenant_id, 'testtenant')

    def test_tenant_id_trumps_tenant(self):
        self.request.headers['X_TENANT_ID'] = 'testtenantid'
        self.request.headers['X_TENANT'] = 'testtenant'
        self.request.headers['X_USER_ID'] = 'testuserid'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.tenant_id, 'testtenantid')

    def test_roles_no_admin(self):
        self.request.headers['X_TENANT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        self.request.headers['X_ROLE'] = 'role1, role2 , role3,role4,role5'
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.roles, ['role1', 'role2', 'role3',
                                              'role4', 'role5'])
        self.assertEqual(self.context.is_admin, False)

    def test_roles_with_admin(self):
        self.request.headers['X_TENANT_ID'] = 'testtenantid'
        self.request.headers['X_USER_ID'] = 'testuserid'
        self.request.headers['X_ROLE'] = ('role1, role2 , role3,role4,role5,'
                                          'AdMiN')
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(self.context.roles, ['role1', 'role2', 'role3',
                                              'role4', 'role5', 'AdMiN'])
        self.assertEqual(self.context.is_admin, True)
