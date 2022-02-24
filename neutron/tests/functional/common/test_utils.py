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
from oslo_utils import uuidutils
import testtools

from neutron.common import utils
from neutron.db import models_v2
from neutron.tests.functional import base
from neutron.tests.unit import testlib_api


class TestWaitUntilTrue(base.BaseLoggingTestCase):
    def test_wait_until_true_predicate_succeeds(self):
        utils.wait_until_true(lambda: True)

    def test_wait_until_true_predicate_fails(self):
        with testtools.ExpectedException(utils.WaitTimeout):
            utils.wait_until_true(lambda: False, 2)


class _TestIsSessionActive(testlib_api.SqlTestCase):

    DRIVER = None

    def setUp(self):
        if not self.DRIVER:
            self.skipTest('No driver defined')
        super().setUp()

    def test_1(self):
        context = n_context.Context(user_id=None, tenant_id=None,
                                    is_admin=True, overwrite=False)
        self.assertFalse(utils.is_session_active(context.session))
        with db_api.CONTEXT_WRITER.using(context):
            net = models_v2.Network(id=uuidutils.generate_uuid())
            context.session.add(net)
            self.assertTrue(utils.is_session_active(context.session))

        self.assertFalse(utils.is_session_active(context.session))


class TestIsSessionActivePostgreSQL(testlib_api.PostgreSQLTestCaseMixin,
                                    _TestIsSessionActive):
    pass


class TestIsSessionActiveMySQL(testlib_api.MySQLTestCaseMixin,
                               _TestIsSessionActive):
    pass
