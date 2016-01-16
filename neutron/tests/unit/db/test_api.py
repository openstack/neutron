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
import testtools

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
