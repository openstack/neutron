# Copyright 2012 VMware, Inc.
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

import mock
from oslo_context import context as oslo_context
from testtools import matchers

from neutron import context
from neutron.tests import base


class TestNeutronContext(base.BaseTestCase):

    def setUp(self):
        super(TestNeutronContext, self).setUp()
        db_api = 'neutron.db.api.get_session'
        self._db_api_session_patcher = mock.patch(db_api)
        self.db_api_session = self._db_api_session_patcher.start()

    def test_neutron_context_create(self):
        ctx = context.Context('user_id', 'tenant_id')
        self.assertEqual('user_id', ctx.user_id)
        self.assertEqual('tenant_id', ctx.project_id)
        self.assertEqual('tenant_id', ctx.tenant_id)
        self.assertThat(ctx.request_id, matchers.StartsWith('req-'))
        self.assertEqual('user_id', ctx.user)
        self.assertEqual('tenant_id', ctx.tenant)
        self.assertIsNone(ctx.user_name)
        self.assertIsNone(ctx.tenant_name)
        self.assertIsNone(ctx.auth_token)

    def test_neutron_context_create_with_name(self):
        ctx = context.Context('user_id', 'tenant_id',
                              tenant_name='tenant_name', user_name='user_name')
        # Check name is set
        self.assertEqual('user_name', ctx.user_name)
        self.assertEqual('tenant_name', ctx.tenant_name)
        # Check user/tenant contains its ID even if user/tenant_name is passed
        self.assertEqual('user_id', ctx.user)
        self.assertEqual('tenant_id', ctx.tenant)

    def test_neutron_context_create_with_request_id(self):
        ctx = context.Context('user_id', 'tenant_id', request_id='req_id_xxx')
        self.assertEqual('req_id_xxx', ctx.request_id)

    def test_neutron_context_create_with_auth_token(self):
        ctx = context.Context('user_id', 'tenant_id',
                              auth_token='auth_token_xxx')
        self.assertEqual('auth_token_xxx', ctx.auth_token)

    def test_neutron_context_to_dict(self):
        ctx = context.Context('user_id', 'tenant_id')
        ctx_dict = ctx.to_dict()
        self.assertEqual('user_id', ctx_dict['user_id'])
        self.assertEqual('tenant_id', ctx_dict['project_id'])
        self.assertEqual(ctx.request_id, ctx_dict['request_id'])
        self.assertEqual('user_id', ctx_dict['user'])
        self.assertEqual('tenant_id', ctx_dict['tenant'])
        self.assertIsNone(ctx_dict['user_name'])
        self.assertIsNone(ctx_dict['tenant_name'])
        self.assertIsNone(ctx_dict['project_name'])
        self.assertIsNone(ctx_dict['auth_token'])

    def test_neutron_context_to_dict_with_name(self):
        ctx = context.Context('user_id', 'tenant_id',
                              tenant_name='tenant_name', user_name='user_name')
        ctx_dict = ctx.to_dict()
        self.assertEqual('user_name', ctx_dict['user_name'])
        self.assertEqual('tenant_name', ctx_dict['tenant_name'])
        self.assertEqual('tenant_name', ctx_dict['project_name'])

    def test_neutron_context_to_dict_with_auth_token(self):
        ctx = context.Context('user_id', 'tenant_id',
                              auth_token='auth_token_xxx')
        ctx_dict = ctx.to_dict()
        self.assertEqual('auth_token_xxx', ctx_dict['auth_token'])

    def test_neutron_context_admin_to_dict(self):
        self.db_api_session.return_value = 'fakesession'
        ctx = context.get_admin_context()
        ctx_dict = ctx.to_dict()
        self.assertIsNone(ctx_dict['user_id'])
        self.assertIsNone(ctx_dict['tenant_id'])
        self.assertIsNone(ctx_dict['auth_token'])
        self.assertIsNotNone(ctx.session)
        self.assertNotIn('session', ctx_dict)

    def test_neutron_context_admin_without_session_to_dict(self):
        ctx = context.get_admin_context_without_session()
        ctx_dict = ctx.to_dict()
        self.assertIsNone(ctx_dict['user_id'])
        self.assertIsNone(ctx_dict['tenant_id'])
        self.assertIsNone(ctx_dict['auth_token'])
        self.assertFalse(hasattr(ctx, 'session'))

    def test_neutron_context_with_load_roles_true(self):
        ctx = context.get_admin_context()
        self.assertIn('admin', ctx.roles)

    def test_neutron_context_with_load_roles_false(self):
        ctx = context.get_admin_context(load_admin_roles=False)
        self.assertFalse(ctx.roles)

    def test_neutron_context_elevated_retains_request_id(self):
        ctx = context.Context('user_id', 'tenant_id')
        self.assertFalse(ctx.is_admin)
        req_id_before = ctx.request_id

        elevated_ctx = ctx.elevated()
        self.assertTrue(elevated_ctx.is_admin)
        self.assertEqual(req_id_before, elevated_ctx.request_id)

    def test_neutron_context_overwrite(self):
        ctx1 = context.Context('user_id', 'tenant_id')
        self.assertEqual(ctx1.request_id,
                         oslo_context.get_current().request_id)

        # If overwrite is not specified, request_id should be updated.
        ctx2 = context.Context('user_id', 'tenant_id')
        self.assertNotEqual(ctx2.request_id, ctx1.request_id)
        self.assertEqual(ctx2.request_id,
                         oslo_context.get_current().request_id)

        # If overwrite is specified, request_id should be kept.
        ctx3 = context.Context('user_id', 'tenant_id', overwrite=False)
        self.assertNotEqual(ctx3.request_id, ctx2.request_id)
        self.assertEqual(ctx2.request_id,
                         oslo_context.get_current().request_id)

    def test_neutron_context_get_admin_context_not_update_local_store(self):
        ctx = context.Context('user_id', 'tenant_id')
        req_id_before = oslo_context.get_current().request_id
        self.assertEqual(ctx.request_id, req_id_before)

        ctx_admin = context.get_admin_context()
        self.assertEqual(req_id_before, oslo_context.get_current().request_id)
        self.assertNotEqual(req_id_before, ctx_admin.request_id)
