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

import testtools

from neutron import context
from neutron.db import common_db_mixin
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup
from neutron.tests.unit import testlib_api


class SecurityGroupDbMixinImpl(securitygroups_db.SecurityGroupDbMixin,
                               common_db_mixin.CommonDbMixin):
    pass


class SecurityGroupDbMixinTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(SecurityGroupDbMixinTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.mixin = SecurityGroupDbMixinImpl()

    def test_delete_security_group_rule_raise_error_on_not_found(self):
        with testtools.ExpectedException(
            securitygroup.SecurityGroupRuleNotFound):
            self.mixin.delete_security_group_rule(self.ctx, 'foo_rule')
