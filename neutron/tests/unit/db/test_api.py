#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_db import exception as db_exc
from sqlalchemy.orm import exc
import testtools

from neutron.common import exceptions
from neutron.db import api as db_api
from neutron.tests import base


class TestExceptionToRetryContextManager(base.BaseTestCase):

    def test_translates_single_exception(self):
        with testtools.ExpectedException(db_exc.RetryRequest):
            with db_api.exc_to_retry(ValueError):
                raise ValueError()

    def test_translates_multiple_exception_types(self):
        with testtools.ExpectedException(db_exc.RetryRequest):
            with db_api.exc_to_retry((ValueError, TypeError)):
                raise TypeError()

    def test_passes_other_exceptions(self):
        with testtools.ExpectedException(ValueError):
            with db_api.exc_to_retry(TypeError):
                raise ValueError()

    def test_inner_exception_preserved_in_retryrequest(self):
        try:
            exc = ValueError('test')
            with db_api.exc_to_retry(ValueError):
                raise exc
        except db_exc.RetryRequest as e:
            self.assertEqual(exc, e.inner_exc)

    def test_retries_on_multi_exception_containing_target(self):
        with testtools.ExpectedException(db_exc.RetryRequest):
            with db_api.exc_to_retry(ValueError):
                e = exceptions.MultipleExceptions([ValueError(), TypeError()])
                raise e


class TestDeadLockDecorator(base.BaseTestCase):

    @db_api.retry_db_errors
    def _decorated_function(self, fail_count, exc_to_raise):
        self.fail_count = getattr(self, 'fail_count', fail_count + 1) - 1
        if self.fail_count:
            raise exc_to_raise

    def test_regular_exception_excluded(self):
        with testtools.ExpectedException(ValueError):
            self._decorated_function(1, ValueError)

    def test_staledata_error_caught(self):
        e = exc.StaleDataError()
        self.assertIsNone(self._decorated_function(1, e))

    def test_multi_exception_contains_retry(self):
        e = exceptions.MultipleExceptions(
            [ValueError(), db_exc.RetryRequest(TypeError())])
        self.assertIsNone(self._decorated_function(1, e))

    def test_multi_exception_contains_deadlock(self):
        e = exceptions.MultipleExceptions([ValueError(), db_exc.DBDeadlock()])
        self.assertIsNone(self._decorated_function(1, e))

    def test_multi_nested_exception_contains_deadlock(self):
        i = exceptions.MultipleExceptions([ValueError(), db_exc.DBDeadlock()])
        e = exceptions.MultipleExceptions([ValueError(), i])
        self.assertIsNone(self._decorated_function(1, e))

    def test_multi_exception_raised_on_exceed(self):
        e = exceptions.MultipleExceptions([ValueError(), db_exc.DBDeadlock()])
        with testtools.ExpectedException(exceptions.MultipleExceptions):
            self._decorated_function(db_api.MAX_RETRIES + 1, e)

    def test_mysql_savepoint_error(self):
        e = db_exc.DBError("(pymysql.err.InternalError) (1305, u'SAVEPOINT "
                           "sa_savepoint_1 does not exist')")
        self.assertIsNone(self._decorated_function(1, e))
