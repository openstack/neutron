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


class FlavorAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(FlavorAPITestCase, self).setUp()
        self.target = {'project_id': self.project_id}


class SystemAdminTests(FlavorAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_flavor(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_flavor', self.target))

    def test_get_flavor(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_flavor', self.target))

    def test_update_flavor(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_flavor', self.target))

    def test_delete_flavor(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_flavor', self.target))

    def test_create_service_profile(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_service_profile', self.target))

    def test_get_service_profile(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_service_profile', self.target))

    def test_update_service_profile(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_service_profile', self.target))

    def test_delete_service_profile(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_service_profile', self.target))

    def test_create_flavor_service_profile(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_flavor_service_profile', self.target))

    def test_delete_flavor_service_profile(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_flavor_service_profile', self.target))


class SystemMemberTests(FlavorAPITestCase):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx

    def test_create_flavor(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_flavor', self.target)

    def test_get_flavor(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_flavor', self.target))

    def test_update_flavor(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_flavor', self.target)

    def test_delete_flavor(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_flavor', self.target)

    def test_create_service_profile(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_service_profile', self.target)

    def test_get_service_profile(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_service_profile', self.target))

    def test_update_service_profile(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_service_profile', self.target)

    def test_delete_service_profile(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_service_profile', self.target)

    def test_create_flavor_service_profile(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_flavor_service_profile',
            self.target)

    def test_delete_flavor_service_profile(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_flavor_service_profile',
            self.target)


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class ProjectAdminTests(FlavorAPITestCase):

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_flavor(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_flavor', self.target)

    def test_update_flavor(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_flavor', self.target)

    def test_delete_flavor(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_flavor', self.target)

    def test_create_service_profile(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_service_profile', self.target)

    def test_update_service_profile(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_service_profile', self.target)

    def test_delete_service_profile(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_service_profile', self.target)

    def test_create_flavor_service_profile(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_flavor_service_profile',
            self.target)

    def test_delete_flavor_service_profile(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_flavor_service_profile',
            self.target)


class ProjectMemberTests(ProjectAdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx
