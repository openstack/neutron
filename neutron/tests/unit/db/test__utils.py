# Copyright 2016
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

from unittest import mock

from neutron_lib import context

from neutron.db import _utils as db_utils
from neutron.tests.unit import testlib_api


class TestCommonHelpFunctions(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestCommonHelpFunctions, self).setUp()
        self.admin_ctx = context.get_admin_context()

    def test__safe_creation_create_bindings_fails(self):
        create_fn = mock.Mock(return_value={'id': 1234})
        create_bindings = mock.Mock(side_effect=ValueError)
        tx_check = lambda i: setattr(self, '_active',
                                     self.admin_ctx.session.is_active)
        delete_fn = mock.Mock(side_effect=tx_check)
        self.assertRaises(ValueError, db_utils.safe_creation,
                          self.admin_ctx, create_fn, delete_fn,
                          create_bindings)
        delete_fn.assert_called_once_with(1234)
        self.assertTrue(self._active)

    def test__safe_creation_deletion_fails(self):
        create_fn = mock.Mock(return_value={'id': 1234})
        create_bindings = mock.Mock(side_effect=ValueError)
        delete_fn = mock.Mock(side_effect=EnvironmentError)
        self.assertRaises(ValueError, db_utils.safe_creation,
                          self.admin_ctx, create_fn, delete_fn,
                          create_bindings)
        delete_fn.assert_called_once_with(1234)
