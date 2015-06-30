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

import mock
import testtools

from neutron.callbacks import exceptions
from neutron.callbacks import registry
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

    def test_create_security_group_conflict(self):
        with mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            secgroup = {'security_group': mock.ANY}
            with testtools.ExpectedException(
                securitygroup.SecurityGroupConflict):
                self.mixin.create_security_group(self.ctx, secgroup)

    def test_delete_security_group_in_use(self):
        with mock.patch.object(self.mixin,
                               '_get_port_security_group_bindings'),\
                mock.patch.object(self.mixin, '_get_security_group'),\
                mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            with testtools.ExpectedException(
                securitygroup.SecurityGroupInUse):
                self.mixin.delete_security_group(self.ctx, mock.ANY)

    def test_update_security_group_conflict(self):
        with mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            secgroup = {'security_group': mock.ANY}
            with testtools.ExpectedException(
                securitygroup.SecurityGroupConflict):
                self.mixin.update_security_group(self.ctx, 'foo_id', secgroup)

    def test_create_security_group_rule_conflict(self):
        with mock.patch.object(self.mixin, '_validate_security_group_rule'),\
                mock.patch.object(self.mixin,
                                  '_check_for_duplicate_rules_in_db'),\
                mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            with testtools.ExpectedException(
                securitygroup.SecurityGroupConflict):
                self.mixin.create_security_group_rule(
                    self.ctx, mock.MagicMock())

    def test_delete_security_group_rule_in_use(self):
        with mock.patch.object(registry, "notify") as mock_notify:
            mock_notify.side_effect = exceptions.CallbackFailure(Exception())
            with testtools.ExpectedException(
                securitygroup.SecurityGroupRuleInUse):
                self.mixin.delete_security_group_rule(self.ctx, mock.ANY)

    def test_delete_security_group_rule_raise_error_on_not_found(self):
        with testtools.ExpectedException(
            securitygroup.SecurityGroupRuleNotFound):
            self.mixin.delete_security_group_rule(self.ctx, 'foo_rule')
