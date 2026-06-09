# Copyright (c) 2026 Red Hat, LLC
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


class PvlanAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminTests(PvlanAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    # Port attributes -- pvlan_type and pvlan_community share the same
    # check_str, so they are tested together here.

    def test_create_port_pvlan(self):
        for attr in ('pvlan_type', 'pvlan_community'):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'create_port:%s' % attr, self.target)
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'create_port:%s' % attr, self.alt_target)

    def test_update_port_pvlan(self):
        for attr in ('pvlan_type', 'pvlan_community'):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'update_port:%s' % attr, self.target)
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'update_port:%s' % attr, self.alt_target)

    def test_get_port_pvlan(self):
        for attr in ('pvlan_type', 'pvlan_community'):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_port:%s' % attr, self.target)
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_port:%s' % attr, self.alt_target)

    # Network attributes

    def test_create_network_pvlan(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:pvlan', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:pvlan', self.alt_target)

    def test_update_network_pvlan(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:pvlan', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:pvlan', self.alt_target)

    def test_get_network_pvlan(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:pvlan', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:pvlan', self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminTests(PvlanAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    # Port attributes

    def test_create_port_pvlan_type(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_port:pvlan_type', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_port:pvlan_type', self.alt_target))

    def test_create_port_pvlan_community(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_port:pvlan_community', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_port:pvlan_community', self.alt_target))

    def test_update_port_pvlan_type(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_port:pvlan_type', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_port:pvlan_type', self.alt_target))

    def test_update_port_pvlan_community(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_port:pvlan_community', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_port:pvlan_community', self.alt_target))

    def test_get_port_pvlan_type(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:pvlan_type', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:pvlan_type', self.alt_target))

    def test_get_port_pvlan_community(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:pvlan_community', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:pvlan_community', self.alt_target))

    # Network attributes

    def test_create_network_pvlan(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_network:pvlan', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_network:pvlan', self.alt_target))

    def test_update_network_pvlan(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_network:pvlan', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_network:pvlan', self.alt_target))

    def test_get_network_pvlan(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_network:pvlan', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_network:pvlan', self.alt_target))


class ProjectManagerTests(PvlanAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    # Port attributes

    def test_create_port_pvlan_type(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_port:pvlan_type', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:pvlan_type', self.alt_target)

    def test_create_port_pvlan_community(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_port:pvlan_community', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:pvlan_community', self.alt_target)

    def test_update_port_pvlan_type(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_port:pvlan_type', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:pvlan_type', self.alt_target)

    def test_update_port_pvlan_community(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_port:pvlan_community', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:pvlan_community', self.alt_target)

    def test_get_port_pvlan_type(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:pvlan_type', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_port:pvlan_type', self.alt_target)

    def test_get_port_pvlan_community(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_port:pvlan_community', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_port:pvlan_community', self.alt_target)

    # Network attributes

    def test_create_network_pvlan(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_network:pvlan', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:pvlan', self.alt_target)

    def test_update_network_pvlan(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_network:pvlan', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:pvlan', self.alt_target)

    def test_get_network_pvlan(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_network:pvlan', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:pvlan', self.alt_target)


class ProjectMemberTests(ProjectManagerTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx

    def test_create_port_pvlan_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:pvlan_type', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:pvlan_type', self.alt_target)

    def test_create_port_pvlan_community(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:pvlan_community', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_port:pvlan_community', self.alt_target)

    def test_update_port_pvlan_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:pvlan_type', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:pvlan_type', self.alt_target)

    def test_update_port_pvlan_community(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:pvlan_community', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_port:pvlan_community', self.alt_target)

    def test_create_network_pvlan(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:pvlan', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:pvlan', self.alt_target)

    def test_update_network_pvlan(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:pvlan', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:pvlan', self.alt_target)


class ServiceRoleTests(PvlanAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    # Port attributes -- pvlan_type and pvlan_community share the same
    # check_str, so they are tested together here.

    def test_create_port_pvlan(self):
        for attr in ('pvlan_type', 'pvlan_community'):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_port:%s' % attr, self.target)

    def test_update_port_pvlan(self):
        for attr in ('pvlan_type', 'pvlan_community'):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_port:%s' % attr, self.target)

    def test_get_port_pvlan(self):
        for attr in ('pvlan_type', 'pvlan_community'):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_port:%s' % attr, self.target)

    # Network attributes

    def test_create_network_pvlan(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:pvlan', self.target)

    def test_update_network_pvlan(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:pvlan', self.target)

    def test_get_network_pvlan(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:pvlan', self.target)
