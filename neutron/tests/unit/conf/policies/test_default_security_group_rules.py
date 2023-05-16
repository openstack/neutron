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

from oslo_policy import policy as base_policy

from neutron import policy
from neutron.tests.unit.conf.policies import test_base as base


class DefaultSecurityGroupRuleAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(DefaultSecurityGroupRuleAPITestCase, self).setUp()
        self.target = {}


class SystemAdminDefaultSecurityGroupRuleTests(
        DefaultSecurityGroupRuleAPITestCase):

    def setUp(self):
        super(SystemAdminDefaultSecurityGroupRuleTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_default_security_group_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_default_security_group_rule', self.target)

    def test_get_default_security_group_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_default_security_group_rule', self.target)

    def test_delete_default_security_group_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_default_security_group_rule', self.target)


class SystemMemberDefaultSecurityGroupRuleTests(
        SystemAdminDefaultSecurityGroupRuleTests):

    def setUp(self):
        super(SystemMemberDefaultSecurityGroupRuleTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderDefaultSecurityGroupRuleTests(
        SystemMemberDefaultSecurityGroupRuleTests):

    def setUp(self):
        super(SystemReaderDefaultSecurityGroupRuleTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminDefaultSecurityGroupRuleTests(DefaultSecurityGroupRuleAPITestCase):

    def setUp(self):
        super(AdminDefaultSecurityGroupRuleTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_default_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_default_security_group_rule', self.target))

    def test_get_default_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_default_security_group_rule', self.target))

    def test_delete_default_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_default_security_group_rule', self.target))


class ProjectMemberDefaultSecurityGroupRuleTests(
        AdminDefaultSecurityGroupRuleTests):

    def setUp(self):
        super(ProjectMemberDefaultSecurityGroupRuleTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_default_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_default_security_group_rule', self.target)

    def test_get_default_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_default_security_group_rule', self.target))

    def test_delete_default_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_default_security_group_rule', self.target)


class ProjectReaderDefaultSecurityGroupRuleTests(
        ProjectMemberDefaultSecurityGroupRuleTests):

    def setUp(self):
        super(ProjectReaderDefaultSecurityGroupRuleTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_create_default_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_default_security_group_rule', self.target)

    def test_delete_default_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_default_security_group_rule', self.target)
