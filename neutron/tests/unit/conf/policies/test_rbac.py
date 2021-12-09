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

from oslo_policy import policy as base_policy
import testscenarios

from neutron import policy
from neutron.tests.unit.conf.policies import test_base as base


class RbacAPITestCase(testscenarios.WithScenarios, base.PolicyBaseTestCase):

    scenarios = [
        ('target_tenant', {'_target_label': 'target_tenant'}),
        ('target_project', {'_target_label': 'target_project'})
    ]

    def setUp(self):
        super(RbacAPITestCase, self).setUp()
        self.target = {
            'project_id': self.project_id,
            self._target_label: 'other-project'}
        self.alt_target = {
            'project_id': self.alt_project_id,
            self._target_label: 'other-project'}
        self.wildcard_target = {
            'project_id': self.project_id,
            self._target_label: '*'}
        self.wildcard_alt_target = {
            'project_id': self.alt_project_id,
            self._target_label: '*'}


class SystemAdminTests(RbacAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_rbac_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_rbac_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_rbac_policy', self.alt_target)

    def test_create_rbac_policy_target_tenant(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_rbac_policy:target_tenant',
            self.wildcard_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_rbac_policy:target_tenant',
            self.wildcard_alt_target)

    def test_update_rbac_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_rbac_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_rbac_policy', self.alt_target)

    def test_update_rbac_policy_target_tenant(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_rbac_policy:target_tenant',
            self.wildcard_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_rbac_policy:target_tenant',
            self.wildcard_alt_target)

    def test_get_rbac_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_rbac_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_rbac_policy', self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class ProjectAdminTests(RbacAPITestCase):

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_rbac_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_rbac_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_rbac_policy', self.alt_target)

    def test_create_rbac_policy_target_tenant(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_rbac_policy:target_tenant', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_rbac_policy:target_tenant',
            self.wildcard_alt_target)

    def test_update_rbac_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_rbac_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_rbac_policy', self.alt_target)

    def test_update_rbac_policy_target_tenant(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_rbac_policy:target_tenant', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_rbac_policy:target_tenant',
            self.wildcard_alt_target)

    def test_get_rbac_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_rbac_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_rbac_policy', self.alt_target)

    def test_delete_rbac_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_rbac_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_rbac_policy', self.alt_target)


class ProjectMemberTests(ProjectAdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_rbac_policy_target_tenant(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_rbac_policy:target_tenant',
            self.wildcard_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_rbac_policy:target_tenant',
            self.wildcard_alt_target)

    def test_update_rbac_policy_target_tenant(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_rbac_policy:target_tenant',
            self.wildcard_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_rbac_policy:target_tenant',
            self.wildcard_alt_target)


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_create_rbac_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_rbac_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_rbac_policy', self.alt_target)

    def test_update_rbac_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_rbac_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_rbac_policy', self.alt_target)

    def test_delete_rbac_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_rbac_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_rbac_policy', self.alt_target)
