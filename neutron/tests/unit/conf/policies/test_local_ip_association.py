# Copyright 2021 Huawei, Inc.
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


class LocalIPAssociationAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.local_ip = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.project_id}
        self.alt_local_ip = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.alt_project_id}

        self.target = {
            'local_ip_id': self.local_ip['id'],
            'ext_parent_local_ip_id': self.local_ip['id']}
        self.alt_target = {
            'local_ip_id': self.alt_local_ip['id'],
            'ext_parent_local_ip_id': self.alt_local_ip['id']}

        local_ips = {
            self.local_ip['id']: self.local_ip,
            self.alt_local_ip['id']: self.alt_local_ip,
        }

        def get_local_ip(context, lip_id, fields=None):
            return local_ips[lip_id]

        self.plugin_mock = mock.Mock()
        self.plugin_mock.get_local_ip.side_effect = get_local_ip
        mock.patch(
            'neutron_lib.plugins.directory.get_plugin',
            return_value=self.plugin_mock).start()


class SystemAdminTests(LocalIPAssociationAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_create_local_ip_port_association(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_local_ip_port_association',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_local_ip_port_association',
            self.alt_target)

    def test_get_local_ip_port_association(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_local_ip_port_association',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_local_ip_port_association',
            self.alt_target)

    def test_delete_local_ip_port_association(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_local_ip_port_association',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_local_ip_port_association',
            self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminTests(LocalIPAssociationAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_create_local_ip_port_association(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_local_ip_port_association',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_local_ip_port_association',
                           self.alt_target))

    def test_get_local_ip_port_association(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_local_ip_port_association',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'get_local_ip_port_association',
                           self.alt_target))

    def test_delete_local_ip_port_association(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_local_ip_port_association',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_local_ip_port_association',
                           self.alt_target))


class ProjectManagerTests(AdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_create_local_ip_port_association(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_local_ip_port_association',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_local_ip_port_association',
            self.alt_target)

    def test_get_local_ip_port_association(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'get_local_ip_port_association',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_local_ip_port_association',
            self.alt_target)

    def test_delete_local_ip_port_association(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_local_ip_port_association',
                           self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_local_ip_port_association',
            self.alt_target)


class ProjectMemberTests(ProjectManagerTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx

    def test_create_local_ip_port_association(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_local_ip_port_association',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_local_ip_port_association',
            self.alt_target)

    def test_delete_local_ip_port_association(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_local_ip_port_association',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_local_ip_port_association',
            self.alt_target)


class ServiceRoleTests(LocalIPAssociationAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_create_local_ip_port_association(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_local_ip_port_association',
            self.target)

    def test_get_local_ip_port_association(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_local_ip_port_association',
            self.target)

    def test_delete_local_ip_port_association(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_local_ip_port_association',
            self.target)
