# Copyright 2016 FUJITSU LIMITED
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

from neutron_lib.db import constants as db_const
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base

LONG_NAME_NG = 'x' * (db_const.NAME_FIELD_SIZE + 1)


class MeteringNegativeTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['metering']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('8b3f7c84-9d37-4771-8681-bfd2c07f3c2d')
    def test_create_metering_label_with_too_long_name(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.create_metering_label,
                          name=LONG_NAME_NG)
