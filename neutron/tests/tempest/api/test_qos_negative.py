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

from neutron_lib.db import constants as db_const
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base

LONG_NAME_NG = 'z' * (db_const.NAME_FIELD_SIZE + 1)
LONG_DESCRIPTION_NG = 'z' * (db_const.LONG_DESCRIPTION_FIELD_SIZE + 1)
LONG_TENANT_ID_NG = 'z' * (db_const.PROJECT_ID_FIELD_SIZE + 1)


class QosNegativeTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['qos']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b9dce555-d3b3-11e5-950a-54ee757c77da')
    def test_add_policy_with_too_long_name(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.client.create_qos_policy,
                          LONG_NAME_NG, 'test policy desc1', False)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b9dce444-d3b3-11e5-950a-54ee747c99db')
    def test_add_policy_with_too_long_description(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.client.create_qos_policy,
                          'test-policy', LONG_DESCRIPTION_NG, False)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('b9dce444-d3b3-11e5-950a-54ee757c77dc')
    def test_add_policy_with_too_long_tenant_id(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.client.create_qos_policy,
                          'test-policy', 'test policy desc1',
                          False, LONG_TENANT_ID_NG)
