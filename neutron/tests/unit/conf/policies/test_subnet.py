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

from unittest import mock

from oslo_policy import policy as base_policy
from oslo_utils import uuidutils

from neutron import policy
from neutron.tests.unit.conf.policies import test_base as base


class SubnetAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(SubnetAPITestCase, self).setUp()

        self.network = {
            'id': uuidutils.generate_uuid(),
            'tenant_id': self.project_id,
            'project_id': self.project_id}
        self.alt_network = {
            'id': uuidutils.generate_uuid(),
            'tenant_id': self.alt_project_id,
            'project_id': self.alt_project_id}

        networks = {
            self.network['id']: self.network,
            self.alt_network['id']: self.alt_network}

        self.target = {
            'project_id': self.project_id,
            'tenant_id': self.project_id,
            'network_id': self.network['id'],
            'ext_parent_network_id': self.network['id']}
        # This network belongs to "project_id", but not the network that
        # belongs to "alt_project_id".
        self.target_net_alt_target = {
            'project_id': self.project_id,
            'tenant_id': self.project_id,
            'network_id': self.alt_network['id'],
            'ext_parent_network_id': self.alt_network['id']}
        self.alt_target = {
            'project_id': self.alt_project_id,
            'tenant_id': self.alt_project_id,
            'network_id': self.alt_network['id'],
            'ext_parent_network_id': self.alt_network['id']}
        # This is the case where the network belongs to the project but not
        # the subnet.
        self.alt_target_own_net = {
            'project_id': self.alt_project_id,
            'tenant_id': self.alt_project_id,
            'network_id': self.network['id'],
            'ext_parent_network_id': self.network['id']}

        def get_network(context, id, fields=None):
            return networks.get(id)

        self.plugin_mock = mock.Mock()
        self.plugin_mock.get_network.side_effect = get_network
        mock.patch(
            'neutron_lib.plugins.directory.get_plugin',
            return_value=self.plugin_mock).start()


class SystemAdminTests(SubnetAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_create_subnet(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet', self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet', self.alt_target_own_net)

    def test_create_subnet_segment_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet:segment_id', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet:segment_id',
            self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet:segment_id', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet:segment_id', self.alt_target_own_net)

    def test_create_subnet_service_types(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet:service_types', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet:service_types',
            self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet:service_types', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_subnet:service_types',
            self.alt_target_own_net)

    def test_get_subnet(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnet', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnet', self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnet', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnet', self.alt_target_own_net)

    def test_get_subnet_segment_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.alt_target_own_net)

    def test_get_subnets_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnets_tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnets_tags', self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnets_tags', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_subnets_tags', self.alt_target_own_net)

    def test_update_subnet(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet', self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet', self.alt_target_own_net)

    def test_update_subnet_segment_id(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet:segment_id', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet:segment_id',
            self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet:segment_id', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet:segment_id', self.alt_target_own_net)

    def test_update_subnet_service_types(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet:service_types', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet:service_types',
            self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet:service_types', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnet:service_types',
            self.alt_target_own_net)

    def test_update_subnets_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnets_tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnets_tags', self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnets_tags', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_subnets_tags', self.alt_target_own_net)

    def test_delete_subnet(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnet', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnet', self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnet', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnet', self.alt_target_own_net)

    def test_delete_subnets_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.target_net_alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.alt_target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.alt_target_own_net)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminTests(SubnetAPITestCase):

    def setUp(self):
        super(AdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_create_subnet(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_subnet', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_subnet',
                           self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'create_subnet', self.alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'create_subnet',
                           self.alt_target_own_net))

    def test_create_subnet_segment_id(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnet:segment_id', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnet:segment_id',
                self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnet:segment_id', self.alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnet:segment_id',
                self.alt_target_own_net))

    def test_create_subnet_service_types(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnet:service_types', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnet:service_types',
                self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnet:service_types', self.alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_subnet:service_types',
                self.alt_target_own_net))

    def test_get_subnet(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet',
                           self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet', self.alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet',
                           self.alt_target_own_net))

    def test_get_subnet_segment_id(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet:segment_id', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet:segment_id',
                           self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_subnet:segment_id', self.alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_subnet:segment_id',
                self.alt_target_own_net))

    def test_get_subnets_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnets_tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnets_tags',
                           self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnets_tags', self.alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnets_tags',
                           self.alt_target_own_net))

    def test_update_subnet(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_subnet', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnet',
                           self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnet', self.alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnet',
                           self.alt_target_own_net))

    def test_update_subnet_segment_id(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnet:segment_id', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnet:segment_id',
                self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnet:segment_id', self.alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnet:segment_id',
                self.alt_target_own_net))

    def test_update_subnet_service_types(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnet:service_types', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnet:service_types',
                self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_subnet:service_types', self.alt_target))

    def test_update_subnets_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_subnets_tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnets_tags',
                           self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnets_tags',
                           self.alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnets_tags',
                           self.alt_target_own_net))

    def test_delete_subnet(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnet', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnet',
                           self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnet', self.alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnet',
                           self.alt_target_own_net))

    def test_delete_subnets_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnets_tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnets_tags',
                           self.target_net_alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnets_tags',
                           self.alt_target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnets_tags',
                           self.alt_target_own_net))


class ProjectMemberTests(AdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_create_subnet(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_subnet', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet', self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet', self.alt_target)
        self.assertTrue(
            policy.enforce(self.context, 'create_subnet',
                           self.alt_target_own_net))

    def test_create_subnet_segment_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:segment_id', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:segment_id',
            self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:segment_id', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:segment_id', self.alt_target_own_net)

    def test_create_subnet_service_types(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:service_types', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:service_types',
            self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:service_types', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:service_types',
            self.alt_target_own_net)

    def test_get_subnet(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet',
                           self.target_net_alt_target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnet', self.alt_target)
        self.assertTrue(
            policy.enforce(self.context, 'get_subnet',
                           self.alt_target_own_net))

    def test_get_subnet_segment_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.alt_target_own_net)

    def test_get_subnets_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_subnets_tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_subnets_tags',
                           self.target_net_alt_target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnets_tags', self.alt_target)
        self.assertTrue(
            policy.enforce(self.context, 'get_subnets_tags',
                           self.alt_target_own_net))

    def test_update_subnet(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_subnet', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnet',
                           self.target_net_alt_target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet', self.alt_target)
        self.assertTrue(
            policy.enforce(self.context, 'update_subnet',
                           self.alt_target_own_net))

    def test_update_subnet_segment_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:segment_id', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:segment_id',
            self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:segment_id', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:segment_id', self.alt_target_own_net)

    def test_update_subnet_service_types(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:service_types', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:service_types',
            self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:service_types', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:service_types',
            self.alt_target_own_net)

    def test_update_subnets_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_subnets_tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_subnets_tags',
                           self.target_net_alt_target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnets_tags', self.alt_target)
        self.assertTrue(
            policy.enforce(self.context, 'update_subnets_tags',
                           self.alt_target_own_net))

    def test_delete_subnet(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnet', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnet',
                           self.target_net_alt_target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnet', self.alt_target)
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnet',
                           self.alt_target_own_net))

    def test_delete_subnets_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnets_tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnets_tags',
                           self.target_net_alt_target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.alt_target)
        self.assertTrue(
            policy.enforce(self.context, 'delete_subnets_tags',
                           self.alt_target_own_net))


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx

    def test_create_subnet(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet', self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet', self.alt_target_own_net)

    def test_update_subnet(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet', self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet', self.alt_target_own_net)

    def test_update_subnets_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnets_tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnets_tags', self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnets_tags', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnets_tags', self.alt_target_own_net)

    def test_delete_subnet(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnet', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnet', self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnet', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnet', self.alt_target_own_net)

    def test_delete_subnets_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.target_net_alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.alt_target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnets_tags', self.alt_target_own_net)


class ServiceRoleTests(SubnetAPITestCase):

    def setUp(self):
        super(ServiceRoleTests, self).setUp()
        self.context = self.service_ctx

    def test_create_subnet(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet', self.target)

    def test_create_subnet_segment_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:segment_id', self.target)

    def test_create_subnet_service_types(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_subnet:service_types', self.target)

    def test_get_subnet(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnet', self.target)

    def test_get_subnet_segment_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_subnet:segment_id', self.target)

    def test_update_subnet(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet', self.target)

    def test_update_subnet_segment_id(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:segment_id', self.target)

    def test_update_subnet_service_types(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_subnet:service_types', self.target)

    def test_delete_subnet(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_subnet', self.target)
