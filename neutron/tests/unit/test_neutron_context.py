# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
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

from neutron import context
from neutron.tests import base


class TestNeutronContext(base.BaseTestCase):

    def setUp(self):
        super(TestNeutronContext, self).setUp()
        db_api = 'neutron.db.api.get_session'
        self._db_api_session_patcher = mock.patch(db_api)
        self.db_api_session = self._db_api_session_patcher.start()
        self.addCleanup(self._db_api_session_patcher.stop)

    def test_neutron_context_create(self):
        cxt = context.Context('user_id', 'tenant_id')
        self.assertEqual('user_id', cxt.user_id)
        self.assertEqual('tenant_id', cxt.project_id)

    def test_neutron_context_to_dict(self):
        cxt = context.Context('user_id', 'tenant_id')
        cxt_dict = cxt.to_dict()
        self.assertEqual('user_id', cxt_dict['user_id'])
        self.assertEqual('tenant_id', cxt_dict['project_id'])

    def test_neutron_context_admin_to_dict(self):
        self.db_api_session.return_value = 'fakesession'
        cxt = context.get_admin_context()
        cxt_dict = cxt.to_dict()
        self.assertIsNone(cxt_dict['user_id'])
        self.assertIsNone(cxt_dict['tenant_id'])
        self.assertIsNotNone(cxt.session)
        self.assertNotIn('session', cxt_dict)

    def test_neutron_context_admin_without_session_to_dict(self):
        cxt = context.get_admin_context_without_session()
        cxt_dict = cxt.to_dict()
        self.assertIsNone(cxt_dict['user_id'])
        self.assertIsNone(cxt_dict['tenant_id'])
        try:
            cxt.session
        except Exception:
            pass
        else:
            self.assertFalse(True, 'without_session admin context'
                                   'should has no session property!')

    def test_neutron_context_with_load_roles_true(self):
        ctx = context.get_admin_context()
        self.assertIn('admin', ctx.roles)

    def test_neutron_context_with_load_roles_false(self):
        ctx = context.get_admin_context(load_admin_roles=False)
        self.assertFalse(ctx.roles)
