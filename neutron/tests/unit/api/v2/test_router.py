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

from neutron.api.v2 import router
from neutron.tests import base


@mock.patch('neutron.api.v2.router.APIRouter.__init__', return_value=None)
@mock.patch('neutron.pecan_wsgi.app.v2_factory')
class TestRouter(base.BaseTestCase):

    def test_pecan_factory(self, pecan_mock, legacy_mock):
        router.APIRouter.factory({})
        pecan_mock.assert_called_once_with({})
        legacy_mock.assert_not_called()
