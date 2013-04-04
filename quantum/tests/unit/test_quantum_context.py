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

from quantum import context
from quantum.tests import base


class TestQuantumContext(base.BaseTestCase):

    def setUp(self):
        super(TestQuantumContext, self).setUp()
        db_api = 'quantum.db.api.get_session'
        self._db_api_session_patcher = mock.patch(db_api)
        self.db_api_session = self._db_api_session_patcher.start()
        self.addCleanup(self._db_api_session_patcher.stop)

    def testQuantumContextCreate(self):
        cxt = context.Context('user_id', 'tenant_id')
        self.assertEqual('user_id', cxt.user_id)
        self.assertEqual('tenant_id', cxt.project_id)

    def testQuantumContextToDict(self):
        cxt = context.Context('user_id', 'tenant_id')
        cxt_dict = cxt.to_dict()
        self.assertEqual('user_id', cxt_dict['user_id'])
        self.assertEqual('tenant_id', cxt_dict['project_id'])

    def testQuantumContextAdminToDict(self):
        self.db_api_session.return_value = 'fakesession'
        cxt = context.get_admin_context()
        cxt_dict = cxt.to_dict()
        self.assertIsNone(cxt_dict['user_id'])
        self.assertIsNone(cxt_dict['tenant_id'])
        self.assertIsNotNone(cxt.session)
        self.assertFalse('session' in cxt_dict)

    def testQuantumContextAdminWithoutSessionToDict(self):
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
