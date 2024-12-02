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

from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
import testtools

from neutron.common import utils
from neutron.objects import network as network_obj
from neutron.tests.functional import base
from neutron.tests.unit import testlib_api


class TestWaitUntilTrue(base.BaseLoggingTestCase):
    def test_wait_until_true_predicate_succeeds(self):
        utils.wait_until_true(lambda: True)

    def test_wait_until_true_predicate_fails(self):
        with testtools.ExpectedException(utils.WaitTimeout):
            utils.wait_until_true(lambda: False, 2)


class TestIsSessionActive(testlib_api.SqlTestCase,
                          testlib_api.MySQLTestCaseMixin):
    DRIVER = None

    def setUp(self):
        if not self.DRIVER:
            self.skipTest('No driver defined')
        super().setUp()

    def test_is_session_active(self):
        context = n_context.Context(user_id=None, project_id=None,
                                    is_admin=True, overwrite=False)
        self.assertFalse(db_api.is_session_active(context.session))
        with db_api.CONTEXT_WRITER.using(context):
            network_obj.Network(context).create()
            self.assertTrue(db_api.is_session_active(context.session))

        self.assertFalse(db_api.is_session_active(context.session))
