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

GET_POLICY = 'get_auto_allocated_topology'
DELETE_POLICY = 'delete_auto_allocated_topology'


class AutoAllocatedTopologyAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(AutoAllocatedTopologyAPITestCase, self).setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminTests(AutoAllocatedTopologyAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_get_topology(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, GET_POLICY, self.target
        )
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, GET_POLICY, self.alt_target
        )

    def test_delete_topology(self):
        # System admins can delete topologies for any project.
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, DELETE_POLICY, self.target
        )
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, DELETE_POLICY, self.alt_target
        )


class SystemMemberTests(AutoAllocatedTopologyAPITestCase):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx

    def test_delete_topology(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, DELETE_POLICY, self.target
        )
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, DELETE_POLICY, self.alt_target
        )


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminTests(AutoAllocatedTopologyAPITestCase):

    def setUp(self):
        super(AdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_get_topology(self):
        self.assertTrue(
            policy.enforce(self.context, GET_POLICY, self.target))
        self.assertTrue(
            policy.enforce(self.context, GET_POLICY, self.alt_target))

    def test_delete_topology(self):
        self.assertTrue(
            policy.enforce(self.context, DELETE_POLICY, self.target))
        self.assertTrue(
            policy.enforce(self.context, DELETE_POLICY, self.alt_target))


class ProjectMemberTests(AdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_get_topology(self):
        self.assertTrue(policy.enforce(self.context, GET_POLICY, self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, GET_POLICY, self.alt_target
        )

    def test_delete_topology(self):
        # Project members can delete topologies inside project, but not outside
        # project
        self.assertTrue(
            policy.enforce(self.context, DELETE_POLICY, self.target)
        )
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, DELETE_POLICY, self.alt_target
        )


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_delete_topology(self):
        # Project readers can't delete allocation topologies inside or outside
        # of project
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, DELETE_POLICY, self.target
        )
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, DELETE_POLICY, self.alt_target
        )


class ServiceRoleTests(AutoAllocatedTopologyAPITestCase):

    def setUp(self):
        super(ServiceRoleTests, self).setUp()
        self.context = self.service_ctx

    def test_get_topology(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, GET_POLICY, self.target
        )

    def test_delete_topology(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, DELETE_POLICY, self.target
        )
