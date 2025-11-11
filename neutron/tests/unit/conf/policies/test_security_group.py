# Copyright (c) 2021 Red Hat Inc.
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

import copy
import shutil

from unittest import mock

from oslo_policy import policy as base_policy
from oslo_utils import uuidutils

from neutron import policy
from neutron.tests.unit.conf.policies import test_base as base


class SecurityGroupAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminSecurityGroupTests(SecurityGroupAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_create_security_group(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_security_group', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_security_group', self.alt_target)

    def test_create_security_group_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_security_group:tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_security_group:tags', self.alt_target)

    def test_get_security_group(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_security_group', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_security_group', self.alt_target)

    def test_get_security_group_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_security_group:tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_security_group:tags', self.alt_target)

    def test_update_security_group(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_security_group', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_security_group', self.alt_target)

    def test_update_security_group_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_security_group:tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_security_group:tags', self.alt_target)

    def test_delete_security_group(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_security_group', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_security_group', self.alt_target)

    def test_delete_security_group_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_security_group:tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_security_group:tags', self.alt_target)


class SystemMemberSecurityGroupTests(SystemAdminSecurityGroupTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderSecurityGroupTests(SystemMemberSecurityGroupTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminSecurityGroupTests(SecurityGroupAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_create_security_group(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_security_group', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_security_group', self.alt_target))

    def test_create_security_group_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_security_group:tags',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_security_group:tags',
                           self.alt_target))

    def test_get_security_group(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_security_group', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_security_group', self.alt_target))

    def test_get_security_group_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_security_group:tags',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_security_group:tags',
                           self.alt_target))

    def test_update_security_group(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_security_group', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_security_group', self.alt_target))

    def test_update_security_group_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_security_group:tags',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_security_group:tags',
                           self.alt_target))

    def test_delete_security_group(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_security_group', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_security_group', self.alt_target))

    def test_delete_security_group_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_security_group:tags',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_security_group:tags',
                           self.alt_target))


class ProjectManagerSecurityGroupTests(AdminSecurityGroupTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_create_security_group(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_security_group', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group', self.alt_target)

    def test_create_security_group_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_security_group:tags',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group:tags', self.alt_target)

    def test_get_security_group(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_security_group', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_security_group', self.alt_target)

    def test_get_security_group_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_security_group:tags',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized, policy.enforce,
            self.context, 'get_security_group:tags', self.alt_target)

    def test_update_security_group(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_security_group', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_security_group', self.alt_target)

    def test_update_security_group_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_security_group:tags',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_security_group:tags',
            self.alt_target)

    def test_delete_security_group(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_security_group', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group', self.alt_target)

    def test_delete_security_group_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_security_group:tags',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized, policy.enforce,
            self.context, 'delete_security_group:tags', self.alt_target)


class ProjectMemberSecurityGroupTests(ProjectManagerSecurityGroupTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx


class ProjectReaderSecurityGroupTests(ProjectMemberSecurityGroupTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx

    def test_create_security_group(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group', self.alt_target)

    def test_create_security_group_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group:tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group:tags', self.alt_target)

    def test_update_security_group(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_security_group', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_security_group', self.alt_target)

    def test_update_security_group_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_security_group:tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_security_group:tags', self.alt_target)

    def test_delete_security_group(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group', self.alt_target)

    def test_delete_security_group_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group:tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group:tags', self.alt_target)


class ServiceRoleSecurityGroupTests(SecurityGroupAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_create_security_group(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group', self.target)

    def test_create_security_group_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group:tags', self.target)

    def test_get_security_group(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_security_group', self.target)

    def test_update_security_group(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_security_group', self.target)

    def test_delete_security_group(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group', self.target)


class SecurityGroupRuleAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.sg = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.project_id}
        self.alt_sg = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.alt_project_id}

        self.target = {
            'project_id': self.project_id,
            'security_group_id': self.sg['id'],
            'ext_parent:project_id': self.sg['id'],
            'ext_parent_security_group_id': self.sg['id']}
        self.alt_target = {
            'project_id': self.alt_project_id,
            'security_group_id': self.alt_sg['id'],
            'ext_parent:project_id': self.alt_sg['id'],
            'ext_parent_security_group_id': self.alt_sg['id']}

        def get_security_group_mock(context, id,
                                    fields=None, project_id=None):
            if id == self.alt_sg['id']:
                return self.alt_sg
            return self.sg

        self.plugin_mock = mock.Mock()
        self.plugin_mock.get_security_group.side_effect = (
            get_security_group_mock)
        mock.patch(
            'neutron_lib.plugins.directory.get_plugin',
            return_value=self.plugin_mock).start()

    def _delete_temp_dir(self, temp_dir):
        try:
            shutil.rmtree(temp_dir)
        except FileNotFoundError:
            pass

    def override_create_security_group_rule(self):
        self._override_security_group_rule('create_security_group_rule')

    def override_delete_security_group_rule(self):
        self._override_security_group_rule('delete_security_group_rule')

    def _override_security_group_rule(self, rule_name):
        # Admin or (member and not default SG) --> only admin can perform the
        # ``rule_name`` action in the default SG.
        rule = {rule_name:
                'role:admin or (role:member and project_id:%(project_id)s '
                'and not rule:rule_default_sg)'}
        temp_dir, policy_file = base.write_policies(rule)
        self.addCleanup(self._delete_temp_dir, temp_dir)
        self.target['belongs_to_default_sg'] = 'True'
        base.reload_policies(policy_file)
        self.plugin_mock.get_default_security_group.return_value = (
            self.sg['id'])


class SystemAdminSecurityGroupRuleTests(SecurityGroupRuleAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_create_security_group_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_security_group_rule', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_security_group_rule', self.alt_target)

    def test_get_security_group_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_security_group_rule', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_security_group_rule', self.alt_target)

    def test_delete_security_group_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_security_group_rule', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_security_group_rule', self.alt_target)


class SystemMemberSecurityGroupRuleTests(SystemAdminSecurityGroupRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderSecurityGroupRuleTests(SystemMemberSecurityGroupRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminSecurityGroupRuleTests(SecurityGroupRuleAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_create_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_security_group_rule', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_security_group_rule', self.alt_target))

    def test_create_security_group_rule_default_sg(self):
        self.override_create_security_group_rule()
        self.assertTrue(
            policy.enforce(self.context,
                           'create_security_group_rule', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_security_group_rule', self.alt_target))

    def test_get_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_security_group_rule', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'get_security_group_rule', self.alt_target))

    def test_delete_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_security_group_rule', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_security_group_rule', self.alt_target))

    def test_delete_security_group_rule_default_sg(self):
        self.override_delete_security_group_rule()
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_security_group_rule', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_security_group_rule', self.alt_target))


class ProjectManagerSecurityGroupRuleTests(AdminSecurityGroupRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_create_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_security_group_rule', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group_rule', self.alt_target)

        # Test for the SG_OWNER different then current user case:
        target = copy.copy(self.target)
        target['security_group_id'] = self.alt_sg['id']
        target['ext_parent:project_id'] = self.alt_sg['project_id']
        target['ext_parent_security_group_id'] = self.alt_sg['id']
        self.plugin_mock.get_security_group.return_value = self.alt_sg
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group_rule', target)

    def test_create_security_group_rule_default_sg(self):
        self.override_create_security_group_rule()
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group_rule', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group_rule', self.alt_target)

    def test_get_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_security_group_rule', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_security_group_rule', self.alt_target)

    def test_delete_security_group_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_security_group_rule', self.target))
        self.plugin_mock.get_security_group.return_value = self.alt_sg
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group_rule', self.alt_target)

        # Test for the SG_OWNER different then current user case:
        target = copy.copy(self.target)
        target['security_group_id'] = self.alt_sg['id']
        target['ext_parent:project_id'] = self.alt_sg['project_id']
        target['ext_parent_security_group_id'] = self.alt_sg['id']
        self.plugin_mock.get_security_group.return_value = self.alt_sg
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group_rule', target)

    def test_delete_security_group_rule_default_sg(self):
        self.override_delete_security_group_rule()
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group_rule', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group_rule', self.alt_target)


class ProjectMemberSecurityGroupRuleTests(
        ProjectManagerSecurityGroupRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx


class ProjectReaderSecurityGroupRuleTests(ProjectMemberSecurityGroupRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx

    def test_create_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group_rule', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group_rule', self.alt_target)
        # Test for the SG_OWNER different then current user case:
        target = copy.copy(self.target)
        target['security_group_id'] = self.alt_sg['id']
        target['ext_parent:project_id'] = self.alt_sg['project_id']
        target['ext_parent_security_group_id'] = self.alt_sg['id']
        self.plugin_mock.get_security_group.return_value = self.alt_sg
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group_rule', target)

    def test_delete_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group_rule', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group_rule', self.alt_target)
        # Test for the SG_OWNER different then current user case:
        target = copy.copy(self.target)
        target['security_group_id'] = self.alt_sg['id']
        target['ext_parent:project_id'] = self.alt_sg['project_id']
        target['ext_parent_security_group_id'] = self.alt_sg['id']
        self.plugin_mock.get_security_group.return_value = self.alt_sg
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group_rule', target)


class ServiceRoleSecurityGroupRuleTests(SecurityGroupRuleAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_create_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_security_group_rule', self.target)

    def test_get_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_security_group_rule', self.target)

    def test_delete_security_group_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_security_group_rule', self.target)
