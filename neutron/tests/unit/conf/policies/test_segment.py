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


class SegmentAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.target = {}


class SystemAdminTests(SegmentAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_create_segment(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_segment', self.target)

    def test_create_segments_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_segments_tags', self.target)

    def test_get_segment(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_segment', self.target)

    def test_get_segments_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_segments_tags', self.target)

    def test_update_segment(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_segment', self.target)

    def test_update_segments_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_segments_tags', self.target)

    def test_delete_segment(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_segment', self.target)

    def test_delete_segments_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_segments_tags', self.target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminTests(SegmentAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_create_segment(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_segment', self.target))

    def test_create_segments_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_segments_tags', self.target))

    def test_get_segment(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_segment', self.target))

    def test_get_segments_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_segments_tags', self.target))

    def test_update_segment(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_segment', self.target))

    def test_update_segments_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_segments_tags', self.target))

    def test_delete_segment(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_segment', self.target))

    def test_delete_segments_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_segments_tags', self.target))


class ProjectManagerTests(AdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_create_segment(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_segment', self.target)

    def test_create_segments_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_segments_tags', self.target)

    def test_get_segment(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_segment', self.target)

    def test_get_segments_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_segments_tags', self.target)

    def test_update_segment(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_segment', self.target)

    def test_update_segments_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_segments_tags', self.target)

    def test_delete_segment(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_segment', self.target)

    def test_delete_segments_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_segments_tags', self.target)


class ProjectMemberTests(ProjectManagerTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx


class ServiceRoleTests(SegmentAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_create_segment(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_segment', self.target)

    def test_create_segments_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_segments_tags', self.target)

    def test_get_segment(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_segment', self.target)

    def test_update_segment(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_segment', self.target)

    def test_delete_segment(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_segment', self.target)
