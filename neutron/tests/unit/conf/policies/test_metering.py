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

from neutron import policy
from neutron.tests.unit.conf.policies import test_base as base


class MeteringAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(MeteringAPITestCase, self).setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminTests(MeteringAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_metering_label(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_metering_label', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_metering_label', self.alt_target)

    def test_get_metering_label(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_metering_label', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_metering_label', self.alt_target)

    def test_delete_metering_label(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_metering_label', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_metering_label', self.alt_target)

    def test_create_metering_label_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_metering_label_rule', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_metering_label_rule', self.alt_target)

    def test_get_metering_label_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_metering_label_rule', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_metering_label_rule', self.alt_target)

    def test_delete_metering_label_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_metering_label_rule', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_metering_label_rule', self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminTests(MeteringAPITestCase):

    def setUp(self):
        super(AdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_metering_label(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_metering_label', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_metering_label', self.alt_target))

    def test_get_metering_label(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_metering_label', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_metering_label', self.alt_target))

    def test_delete_metering_label(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_metering_label', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_metering_label', self.alt_target))

    def test_create_metering_label_rule(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_metering_label_rule', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_metering_label_rule', self.alt_target))

    def test_get_metering_label_rule(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_metering_label_rule', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_metering_label_rule', self.alt_target))

    def test_delete_metering_label_rule(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_metering_label_rule', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_metering_label_rule', self.alt_target))


class ProjectMemberTests(AdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_metering_label(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_metering_label', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_metering_label', self.alt_target)

    def test_get_metering_label(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_metering_label', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_metering_label', self.alt_target)

    def test_delete_metering_label(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_metering_label', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_metering_label', self.alt_target)

    def test_create_metering_label_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_metering_label_rule', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_metering_label_rule', self.alt_target)

    def test_get_metering_label_rule(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_metering_label_rule', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_metering_label_rule', self.alt_target)

    def test_delete_metering_label_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_metering_label_rule', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_metering_label_rule', self.alt_target)


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx


class ServiceRoleTests(MeteringAPITestCase):

    def setUp(self):
        super(ServiceRoleTests, self).setUp()
        self.context = self.service_ctx

    def test_create_metering_label(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_metering_label', self.target)

    def test_get_metering_label(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_metering_label', self.target)

    def test_delete_metering_label(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_metering_label', self.target)

    def test_create_metering_label_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_metering_label_rule', self.target)

    def test_get_metering_label_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_metering_label_rule', self.target)

    def test_delete_metering_label_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_metering_label_rule', self.target)
