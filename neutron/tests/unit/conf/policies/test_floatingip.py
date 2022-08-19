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


class FloatingIPAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(FloatingIPAPITestCase, self).setUp()
        self.target = {
            'project_id': self.project_id,
            'floating_ip_address': '172.24.4.228'}
        self.alt_target = {
            'project_id': self.alt_project_id,
            'floating_ip_address': '172.24.4.228'}


class SystemAdminTests(FloatingIPAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_floatingip(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "create_floatingip", self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "create_floatingip", self.alt_target)

    def test_create_floatingip_with_ip_address(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "create_floatingip:floating_ip_address",
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "create_floatingip:floating_ip_address",
            self.alt_target)

    def test_get_floatingip(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "get_floatingip", self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "get_floatingip", self.alt_target)

    def test_update_floatingip(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "update_floatingip", self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "update_floatingip", self.alt_target)

    def test_delete_floatingip(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "delete_floatingip", self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "delete_floatingip", self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class ProjectAdminTests(FloatingIPAPITestCase):

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_floatingip(self):
        self.assertTrue(
            policy.enforce(self.context, "create_floatingip", self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "create_floatingip", self.alt_target)

    def test_create_floatingip_with_ip_address(self):
        self.assertTrue(
            policy.enforce(
                self.context,
                "create_floatingip:floating_ip_address", self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "create_floatingip:floating_ip_address",
            self.alt_target)

    def test_get_floatingip(self):
        self.assertTrue(
            policy.enforce(self.context, "get_floatingip", self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, "get_floatingip", self.alt_target)

    def test_update_floatingip(self):
        self.assertTrue(
            policy.enforce(self.context, "update_floatingip", self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, "update_floatingip", self.alt_target)

    def test_delete_floatingip(self):
        self.assertTrue(
            policy.enforce(self.context, "delete_floatingip", self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, "delete_floatingip", self.alt_target)


class ProjectMemberTests(ProjectAdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_floatingip_with_ip_address(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "create_floatingip:floating_ip_address",
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "create_floatingip:floating_ip_address",
            self.alt_target)


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_create_floatingip(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "create_floatingip", self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "create_floatingip", self.alt_target)

    def test_update_floatingip(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "update_floatingip", self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "update_floatingip", self.alt_target)

    def test_delete_floatingip(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "delete_floatingip", self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "delete_floatingip", self.alt_target)
