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


class FloatingipPortForwardingAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.fip = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.project_id}
        self.alt_fip = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.alt_project_id}

        self.target = {
            'floatingip_id': self.fip['id'],
            'ext_parent_floatingip_id': self.fip['id']}
        self.alt_target = {
            'floatingip_id': self.alt_fip['id'],
            'ext_parent_floatingip_id': self.alt_fip['id']}

        self.plugin_mock = mock.Mock()
        self.plugin_mock.get_floatingip.return_value = self.fip
        mock.patch(
            'neutron_lib.plugins.directory.get_plugin',
            return_value=self.plugin_mock).start()


class SystemAdminTests(FloatingipPortForwardingAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_create_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'create_floatingip_port_forwarding',
                self.target)
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'create_floatingip_port_forwarding',
                self.alt_target)

    def test_get_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_floatingip_port_forwarding',
                self.target)
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_floatingip_port_forwarding',
                self.alt_target)

    def test_update_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'update_floatingip_port_forwarding',
                self.target)
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'update_floatingip_port_forwarding',
                self.alt_target)

    def test_delete_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'delete_floatingip_port_forwarding',
                self.target)
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'delete_floatingip_port_forwarding',
                self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminTests(FloatingipPortForwardingAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_create_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'create_floatingip_port_forwarding',
                               self.target))
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'create_floatingip_port_forwarding',
                               self.alt_target))

    def test_get_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_floatingip_port_forwarding',
                               self.target))
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_floatingip_port_forwarding',
                               self.alt_target))

    def test_update_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'update_floatingip_port_forwarding',
                               self.target))
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'update_floatingip_port_forwarding',
                               self.alt_target))

    def test_delete_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_floatingip_port_forwarding',
                               self.target))
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_floatingip_port_forwarding',
                               self.alt_target))


class ProjectManagerTests(AdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_create_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'create_floatingip_port_forwarding',
                               self.target))
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_floatingip_port_forwarding',
                self.alt_target)

    def test_get_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_floatingip_port_forwarding',
                               self.target))
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_floatingip_port_forwarding',
                self.alt_target)

    def test_update_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'update_floatingip_port_forwarding',
                               self.target))
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_floatingip_port_forwarding',
                self.alt_target)

    def test_delete_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_floatingip_port_forwarding',
                               self.target))
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_floatingip_port_forwarding',
                self.alt_target)


class ProjectMemberTests(ProjectManagerTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx

    def test_create_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_floatingip_port_forwarding',
                self.target)
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_floatingip_port_forwarding',
                self.alt_target)

    def test_update_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_floatingip_port_forwarding',
                self.target)
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_floatingip_port_forwarding',
                self.alt_target)

    def test_delete_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_floatingip_port_forwarding',
                self.target)
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.alt_fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_floatingip_port_forwarding',
                self.alt_target)


class ServiceRoleTests(FloatingipPortForwardingAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_create_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_floatingip_port_forwarding',
                self.target)

    def test_get_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_floatingip_port_forwarding',
                self.target)

    def test_update_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_floatingip_port_forwarding',
                self.target)

    def test_delete_fip_pf(self):
        with mock.patch.object(self.plugin_mock, 'get_floatingip',
                               return_value=self.fip):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_floatingip_port_forwarding',
                self.target)
