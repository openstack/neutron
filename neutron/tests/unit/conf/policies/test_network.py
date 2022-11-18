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


class NetworkAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(NetworkAPITestCase, self).setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminTests(NetworkAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_network(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_network', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_network', self.alt_target)

    def test_create_network_shared(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:shared', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:shared', self.alt_target)

    def test_create_network_external(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:router:external', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:router:external', self.alt_target)

    def test_create_network_default(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:is_default', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:is_default', self.alt_target)

    def test_create_network_port_security_enabled(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:port_security_enabled',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:port_security_enabled',
            self.alt_target)

    def test_create_network_segments(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:segments', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:segments', self.alt_target)

    def test_create_network_provider_network_type(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:provider:network_type', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:provider:network_type',
            self.alt_target)

    def test_create_network_provider_physical_network(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:provider:physical_network',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:provider:physical_network',
            self.alt_target)

    def test_create_network_provider_segmentation_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:provider:segmentation_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_network:provider:segmentation_id',
            self.alt_target)

    def test_get_network(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network',
            self.alt_target)

    def test_get_network_segments(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:segments', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:segments', self.alt_target)

    def test_get_network_provider_network_type(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:provider:network_type', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:provider:network_type', self.alt_target)

    def test_get_network_provider_physical_network(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:provider:physical_network',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:provider:physical_network',
            self.alt_target)

    def test_get_network_provider_segmentation_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:provider:segmentation_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network:provider:segmentation_id',
            self.alt_target)

    def test_update_network(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_network', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_network', self.alt_target)

    def test_update_network_segments(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:segments', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:segments', self.alt_target)

    def test_update_network_shared(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:shared', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:shared', self.alt_target)

    def test_update_network_provider_network_type(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:provider:network_type', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:provider:network_type',
            self.alt_target)

    def test_update_network_provider_physical_network(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:provider:physical_network',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:provider:physical_network',
            self.alt_target)

    def test_update_network_provider_segmentation_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:provider:segmentation_id',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:provider:segmentation_id',
            self.alt_target)

    def test_update_network_external(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:router:external', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:router:external', self.alt_target)

    def test_update_network_default(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:is_default', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:is_default', self.alt_target)

    def test_update_network_port_security_enabled(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:port_security_enabled',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_network:port_security_enabled',
            self.alt_target)

    def test_delete_network(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_network', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_network', self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminTests(NetworkAPITestCase):

    def setUp(self):
        super(AdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_network(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_network', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_network', self.alt_target))

    def test_create_network_shared(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_network:shared', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_network:shared', self.alt_target))

    def test_create_network_external(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:router:external', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:router:external', self.alt_target))

    def test_create_network_default(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:is_default', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:is_default', self.alt_target))

    def test_create_network_port_security_enabled(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:port_security_enabled',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:port_security_enabled',
                           self.alt_target))

    def test_create_network_segments(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:segments', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:segments', self.alt_target))

    def test_create_network_provider_network_type(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:provider:network_type',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:provider:network_type',
                           self.alt_target))

    def test_create_network_provider_physical_network(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:provider:physical_network',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:provider:physical_network',
                           self.alt_target))

    def test_create_network_provider_segmentation_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:provider:segmentation_id',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:provider:segmentation_id',
                           self.alt_target))

    def test_get_network(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_network', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_network', self.alt_target))

    def test_get_network_provider_network_type(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_network:provider:network_type',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'get_network:provider:network_type',
                           self.alt_target))

    def test_get_network_provider_physical_network(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_network:provider:physical_network',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'get_network:provider:physical_network',
                           self.alt_target))

    def test_get_network_provider_segmentation_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_network:provider:segmentation_id',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'get_network:provider:segmentation_id',
                           self.alt_target))

    def test_update_network(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_network', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_network', self.alt_target))

    def test_update_network_segments(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:segments', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:segments', self.alt_target))

    def test_update_network_shared(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_network:shared', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_network:shared', self.alt_target))

    def test_update_network_provider_network_type(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:provider:network_type',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:provider:network_type',
                           self.alt_target))

    def test_update_network_provider_physical_network(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:provider:physical_network',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:provider:physical_network',
                           self.alt_target))

    def test_update_network_provider_segmentation_id(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:provider:segmentation_id',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:provider:segmentation_id',
                           self.alt_target))

    def test_update_network_external(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:router:external', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:router:external', self.alt_target))

    def test_update_network_default(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:is_default', self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:is_default', self.alt_target))

    def test_update_network_port_security_enabled(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:port_security_enabled',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:port_security_enabled',
                           self.alt_target))

    def test_delete_network(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_network', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_network', self.alt_target))


class ProjectMemberTests(AdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_network(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_network', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network', self.alt_target)

    def test_create_network_shared(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:shared', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:shared', self.alt_target)

    def test_create_network_external(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:router:external', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:router:external', self.alt_target)

    def test_create_network_default(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:is_default', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:is_default', self.alt_target)

    def test_create_network_port_security_enabled(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_network:port_security_enabled',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:port_security_enabled',
            self.alt_target)

    def test_create_network_segments(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:segments', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:segments', self.alt_target)

    def test_create_network_provider_network_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:provider:network_type', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:provider:network_type',
            self.alt_target)

    def test_create_network_provider_physical_network(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:provider:physical_network',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:provider:physical_network',
            self.alt_target)

    def test_create_network_provider_segmentation_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:provider:segmentation_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:provider:segmentation_id',
            self.alt_target)

    def test_get_network(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_network', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network', self.alt_target)

    def test_get_network_segments(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:segments', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:segments', self.alt_target)

    def test_get_network_provider_network_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:provider:network_type', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:provider:network_type', self.alt_target)

    def test_get_network_provider_physical_network(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:provider:physical_network',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:provider:physical_network',
            self.alt_target)

    def test_get_network_provider_segmentation_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:provider:segmentation_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network:provider:segmentation_id',
            self.alt_target)

    def test_update_network(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_network', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network', self.alt_target)

    def test_update_network_segments(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:segments', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:segments', self.alt_target)

    def test_update_network_shared(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:shared', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:shared', self.alt_target)

    def test_update_network_provider_network_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:provider:network_type', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:provider:network_type',
            self.alt_target)

    def test_update_network_provider_physical_network(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:provider:physical_network',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:provider:physical_network',
            self.alt_target)

    def test_update_network_provider_segmentation_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:provider:segmentation_id',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:provider:segmentation_id',
            self.alt_target)

    def test_update_network_external(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:router:external', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:router:external', self.alt_target)

    def test_update_network_default(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:is_default', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:is_default', self.alt_target)

    def test_update_network_port_security_enabled(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_network:port_security_enabled',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:port_security_enabled',
            self.alt_target)

    def test_delete_network(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_network', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_network', self.alt_target)


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_create_network(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_network', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_network', self.alt_target)

    def test_create_network_port_security_enabled(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:port_security_enabled',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_network:port_security_enabled',
            self.alt_target)

    def test_update_network(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_network', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_network', self.alt_target)

    def test_update_network_port_security_enabled(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:port_security_enabled',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_network:port_security_enabled',
            self.alt_target)

    def test_delete_network(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_network', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_network', self.alt_target)
