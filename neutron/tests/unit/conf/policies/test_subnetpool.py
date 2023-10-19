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


class SubnetpoolAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(SubnetpoolAPITestCase, self).setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminTests(SubnetpoolAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_subnetpool(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnetpool', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnetpool', self.alt_target)

    def test_create_subnetpool_shared(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnetpool:shared', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnetpool:shared', self.alt_target)

    def test_create_subnetpool_default(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnetpool:is_default', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnetpool:is_default', self.alt_target)

    def test_get_subnetpool(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnetpool', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnetpool', self.alt_target)

    def test_get_subnetpools_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnetpools_tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnetpools_tags', self.alt_target)

    def test_update_subnetpool(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnetpool', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnetpool', self.alt_target)

    def test_update_subnetpool_default(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnetpool:is_default', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnetpool:is_default', self.alt_target)

    def test_update_subnetpools_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnetpools_tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnetpools_tags', self.alt_target)

    def test_delete_subnetpool(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnetpool', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnetpool', self.alt_target)

    def test_delete_subnetpools_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnetpools_tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnetpools_tags', self.alt_target)

    def test_onboard_network_subnets(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'onboard_network_subnets', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'onboard_network_subnets', self.alt_target)

    def test_add_prefixes(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'add_prefixes', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'add_prefixes', self.alt_target)

    def test_remove_prefixes(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'remove_prefixes', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'remove_prefixes', self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminTests(SubnetpoolAPITestCase):

    def setUp(self):
        super(AdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_subnetpool(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_subnetpool', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_subnetpool', self.alt_target))

    def test_create_subnetpool_shared(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnetpool:shared', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnetpool:shared', self.alt_target))

    def test_create_subnetpool_default(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnetpool:default', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnetpool:default', self.alt_target))

    def test_get_subnetpool(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnetpool', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnetpool', self.alt_target))

    def test_get_subnetpools_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnetpools_tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnetpools_tags',
                           self.alt_target))

    def test_update_subnetpool(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_subnetpool', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnetpool', self.alt_target))

    def test_update_subnetpool_default(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnetpool:default', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnetpool:default', self.alt_target))

    def test_update_subnetpools_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_subnetpools_tags',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnetpools_tags',
                           self.alt_target))

    def test_delete_subnetpool(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnetpool', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnetpool', self.alt_target))

    def test_delete_subnetpools_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnetpools_tags',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnetpools_tags',
                           self.alt_target))

    def test_onboard_network_subnets(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'onboard_network_subnets', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'onboard_network_subnets', self.alt_target))

    def test_add_prefixes(self):
        self.assertTrue(
            policy.enforce(self.context, 'add_prefixes', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'add_prefixes', self.alt_target))

    def test_remove_prefixes(self):
        self.assertTrue(
            policy.enforce(self.context, 'remove_prefixes', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'remove_prefixes', self.alt_target))


class ProjectMemberTests(AdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_subnetpool(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_subnetpool', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool', self.alt_target)

    def test_create_subnetpool_shared(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool:shared', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool:shared', self.alt_target)

    def test_create_subnetpool_default(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool:is_default', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool:is_default', self.alt_target)

    def test_get_subnetpool(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnetpool', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnetpool', self.alt_target)

    def test_get_subnetpools_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnetpools_tags', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnetpools_tags', self.alt_target)

    def test_update_subnetpool(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_subnetpool', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpool', self.alt_target)

    def test_update_subnetpool_default(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpool:is_default', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpool:is_default', self.alt_target)

    def test_update_subnetpools_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_subnetpools_tags',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpools_tags', self.alt_target)

    def test_delete_subnetpool(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnetpool', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnetpool', self.alt_target)

    def test_delete_subnetpools_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnetpools_tags',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnetpools_tags', self.alt_target)

    def test_onboard_network_subnets(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'onboard_network_subnets', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'onboard_network_subnets', self.alt_target)

    def test_add_prefixes(self):
        self.assertTrue(
            policy.enforce(self.context, 'add_prefixes', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_prefixes', self.alt_target)

    def test_remove_prefixes(self):
        self.assertTrue(
            policy.enforce(self.context, 'remove_prefixes', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_prefixes', self.alt_target)


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_create_subnetpool(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool', self.alt_target)

    def test_update_subnetpool(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpool', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpool', self.alt_target)

    def test_update_subnetpools_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpools_tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpools_tags', self.alt_target)

    def test_delete_subnetpool(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnetpool', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnetpool', self.alt_target)

    def test_delete_subnetpools_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnetpools_tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnetpools_tags', self.alt_target)

    def test_onboard_network_subnets(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'onboard_network_subnets', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'onboard_network_subnets', self.alt_target)

    def test_add_prefixes(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_prefixes', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_prefixes', self.alt_target)

    def test_remove_prefixes(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_prefixes', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_prefixes', self.alt_target)


class ServiceRoleTests(SubnetpoolAPITestCase):

    def setUp(self):
        super(ServiceRoleTests, self).setUp()
        self.context = self.service_ctx

    def test_create_subnetpool(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool', self.target)

    def test_create_subnetpool_shared(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool:shared', self.target)

    def test_create_subnetpool_default(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnetpool:is_default', self.target)

    def test_get_subnetpool(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnetpool', self.target)

    def test_get_subnetpools_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnetpools_tags', self.target)

    def test_update_subnetpool(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpool', self.target)

    def test_update_subnetpool_default(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpool:is_default', self.target)

    def test_update_subnetpools_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnetpools_tags', self.target)

    def test_delete_subnetpool(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnetpool', self.target)

    def test_delete_subnetpools_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnetpools_tags', self.target)

    def test_onboard_network_subnets(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'onboard_network_subnets', self.target)

    def test_add_prefixes(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'add_prefixes', self.target)

    def test_remove_prefixes(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'remove_prefixes', self.target)
