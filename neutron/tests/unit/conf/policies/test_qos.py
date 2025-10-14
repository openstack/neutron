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


class QosPolicyAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminQosPolicyTests(QosPolicyAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_get_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_policy', self.alt_target)

    def test_get_policy_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_policy:tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_policy:tags', self.alt_target)

    def test_create_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_policy', self.alt_target)

    def test_create_policy_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_policy:tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_policy:tags',
            self.alt_target)

    def test_update_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_policy', self.alt_target)

    def test_update_policy_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_policy:tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_policy:tags',
            self.alt_target)

    def test_delete_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_policy', self.alt_target)

    def test_delete_policy_tags(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_policy:tags', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_policy:tags',
            self.alt_target)


class SystemMemberQosPolicyTests(SystemAdminQosPolicyTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderQosPolicyTests(SystemMemberQosPolicyTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminQosPolicyTests(QosPolicyAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_get_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_policy', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_policy', self.alt_target))

    def test_get_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_policy:tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_policy:tags', self.alt_target))

    def test_create_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_policy', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_policy', self.alt_target))

    def test_create_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_policy:tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_policy:tags',
                           self.alt_target))

    def test_update_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_policy', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_policy', self.alt_target))

    def test_update_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_policy:tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_policy:tags',
                           self.alt_target))

    def test_delete_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_policy', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_policy', self.alt_target))

    def test_delete_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_policy:tags', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_policy:tags',
                           self.alt_target))


class ProjectManagerQosPolicyTests(AdminQosPolicyTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_get_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_policy', self.alt_target)

    def test_get_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_policy:tags', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_policy:tags',
            self.alt_target)

    def test_create_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy', self.alt_target)

    def test_create_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_policy:tags', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy:tags',
            self.alt_target)

    def test_update_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy', self.alt_target)

    def test_update_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_policy:tags', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy:tags',
            self.alt_target)

    def test_delete_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy', self.alt_target)

    def test_delete_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_policy:tags', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy:tags',
            self.alt_target)


class ProjectMemberQosPolicyTests(ProjectManagerQosPolicyTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx

    def test_get_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_policy', self.alt_target)

    def test_get_policy_tags(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_policy:tags', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_policy:tags',
            self.alt_target)

    def test_create_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy', self.alt_target)

    def test_create_policy_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy:tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy:tags',
            self.alt_target)

    def test_update_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy', self.alt_target)

    def test_update_policy_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy:tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy:tags',
            self.alt_target)

    def test_delete_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy', self.alt_target)

    def test_delete_policy_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy:tags', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy:tags',
            self.alt_target)


class ProjectReaderQosPolicyTests(ProjectMemberQosPolicyTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx


class ServiceRoleQosPolicyTests(QosPolicyAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_get_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_policy', self.target)

    def test_get_policy_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_policy:tags', self.target)

    def test_create_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy', self.target)

    def test_create_policy_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy:tags', self.target)

    def test_update_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy', self.target)

    def test_update_policy_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy:tags', self.target)

    def test_delete_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy', self.target)

    def test_delete_policy_tags(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy:tags', self.target)


class QosRuleTypeAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.target = {}


class SystemAdminQosRuleTypeTests(QosRuleTypeAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_get_rule_type(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_rule_type', self.target)


class SystemMemberQosRuleTypeTests(SystemAdminQosRuleTypeTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderQosRuleTypeTests(SystemMemberQosRuleTypeTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminQosRuleTypeTests(QosRuleTypeAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_get_rule_type(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_rule_type', self.target))


class ProjectManagerQosRuleTypeTests(AdminQosRuleTypeTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx


class ProjectMemberQosRuleTypeTests(ProjectManagerQosRuleTypeTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx


class ProjectReaderQosRuleTypeTests(ProjectMemberQosRuleTypeTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx


class ServiceRoleQosRuleTypeTests(QosRuleTypeAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_get_rule_type(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_rule_type', self.target)


class QosRulesAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.qos_policy = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.project_id}
        self.alt_qos_policy = {
            'id': uuidutils.generate_uuid(),
            'project_id': self.alt_project_id}
        self.target = {
            'policy_id': self.qos_policy['id'],
            'ext_parent_policy_id': self.qos_policy['id']}
        self.alt_target = {
            'policy_id': self.alt_qos_policy['id'],
            'ext_parent_policy_id': self.alt_qos_policy['id']}

        self.plugin_mock = mock.Mock()
        mock.patch(
            'neutron_lib.plugins.directory.get_plugin',
            return_value=self.plugin_mock).start()


class SystemAdminQosBandwidthLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_get_policy_bandwidth_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_policy_bandwidth_limit_rule',
                self.target)
            # And the same for aliases
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_alias_bandwidth_limit_rule',
                self.target)

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_policy_bandwidth_limit_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_alias_bandwidth_limit_rule',
                self.alt_target)

    def test_create_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_bandwidth_limit_rule',
            self.alt_target)

    def test_update_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_bandwidth_limit_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_alias_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_alias_bandwidth_limit_rule',
            self.alt_target)

    def test_delete_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_bandwidth_limit_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_alias_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_alias_bandwidth_limit_rule',
            self.alt_target)


class SystemMemberQosBandwidthLimitRuleTests(
        SystemAdminQosBandwidthLimitRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderQosBandwidthLimitRuleTests(
        SystemMemberQosBandwidthLimitRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminQosBandwidthLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_get_policy_bandwidth_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_bandwidth_limit_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_bandwidth_limit_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_bandwidth_limit_rule',
                               self.alt_target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_bandwidth_limit_rule',
                               self.alt_target))

    def test_create_policy_bandwidth_limit_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_policy_bandwidth_limit_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_policy_bandwidth_limit_rule',
                           self.alt_target))

    def test_update_policy_bandwidth_limit_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_policy_bandwidth_limit_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_policy_bandwidth_limit_rule',
                           self.alt_target))

        # And the same for aliases
        self.assertTrue(
            policy.enforce(self.context,
                           'update_alias_bandwidth_limit_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_alias_bandwidth_limit_rule',
                           self.alt_target))

    def test_delete_policy_bandwidth_limit_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_policy_bandwidth_limit_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_policy_bandwidth_limit_rule',
                           self.alt_target))

        # And the same for aliases
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_alias_bandwidth_limit_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_alias_bandwidth_limit_rule',
                           self.alt_target))


class ProjectManagerQosBandwidthLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_get_policy_bandwidth_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_bandwidth_limit_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_bandwidth_limit_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_bandwidth_limit_rule',
                self.alt_target)

            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_alias_bandwidth_limit_rule',
                self.alt_target)

    def test_create_policy_bandwidth_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'create_policy_bandwidth_limit_rule',
                               self.target))
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_policy_bandwidth_limit_rule',
                self.alt_target)

    def test_update_policy_bandwidth_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'update_policy_bandwidth_limit_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'update_alias_bandwidth_limit_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_policy_bandwidth_limit_rule',
                self.alt_target)

            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_alias_bandwidth_limit_rule',
                self.alt_target)

    def test_delete_policy_bandwidth_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_policy_bandwidth_limit_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_alias_bandwidth_limit_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_policy_bandwidth_limit_rule',
                self.alt_target)

            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_alias_bandwidth_limit_rule',
                self.alt_target)


class ProjectMemberQosBandwidthLimitRuleTests(
        ProjectManagerQosBandwidthLimitRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx

    def test_create_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_bandwidth_limit_rule',
            self.alt_target)

    def test_update_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_bandwidth_limit_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_bandwidth_limit_rule',
            self.alt_target)

    def test_delete_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_bandwidth_limit_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_bandwidth_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_bandwidth_limit_rule',
            self.alt_target)


class ProjectReaderQosBandwidthLimitRuleTests(
        ProjectMemberQosBandwidthLimitRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx


class ServiceRoleQosBandwidthLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_get_policy_bandwidth_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_bandwidth_limit_rule',
                self.target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_alias_bandwidth_limit_rule',
                self.target)

    def test_create_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_bandwidth_limit_rule',
            self.target)

    def test_update_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_bandwidth_limit_rule',
            self.target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_bandwidth_limit_rule',
            self.target)

    def test_delete_policy_bandwidth_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_bandwidth_limit_rule',
            self.target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_bandwidth_limit_rule',
            self.target)


class SystemAdminQosPacketRateLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_get_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_policy_packet_rate_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_policy_packet_rate_limit_rule',
            self.alt_target)

    def test_create_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_packet_rate_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_packet_rate_limit_rule',
            self.alt_target)

    def test_update_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_packet_rate_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_packet_rate_limit_rule',
            self.alt_target)

    def test_delete_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_packet_rate_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_packet_rate_limit_rule',
            self.alt_target)


class AdminQosPacketRateLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_get_policy_packet_rate_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_packet_rate_limit_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_packet_rate_limit_rule',
                               self.alt_target))

    def test_create_policy_packet_rate_limit_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_policy_packet_rate_limit_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_policy_packet_rate_limit_rule',
                           self.alt_target))

    def test_update_policy_packet_rate_limit_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_policy_packet_rate_limit_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_policy_packet_rate_limit_rule',
                           self.alt_target))

    def test_delete_policy_packet_rate_limit_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_policy_packet_rate_limit_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_policy_packet_rate_limit_rule',
                           self.alt_target))


class ProjectManagerQosPacketRateLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_get_policy_packet_rate_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_packet_rate_limit_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_packet_rate_limit_rule',
                self.alt_target)

    def test_create_policy_packet_rate_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'create_policy_packet_rate_limit_rule',
                               self.target))
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_policy_packet_rate_limit_rule',
                self.alt_target)

    def test_update_policy_packet_rate_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'update_policy_packet_rate_limit_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_policy_packet_rate_limit_rule',
                self.alt_target)

    def test_delete_policy_packet_rate_limit_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_policy_packet_rate_limit_rule',
                               self.target))
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_policy_packet_rate_limit_rule',
                self.alt_target)


class ProjectMemberQosPacketRateLimitRuleTests(
        ProjectManagerQosPacketRateLimitRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx

    def test_create_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_packet_rate_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_packet_rate_limit_rule',
            self.alt_target)

    def test_update_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_packet_rate_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_packet_rate_limit_rule',
            self.alt_target)

    def test_delete_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_packet_rate_limit_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_packet_rate_limit_rule',
            self.alt_target)


class ProjectReaderQosPacketRateLimitRuleTests(
        ProjectMemberQosPacketRateLimitRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx


class ServiceRoleQosPacketRateLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_get_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_policy_packet_rate_limit_rule',
            self.target)

    def test_create_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_packet_rate_limit_rule',
            self.target)

    def test_update_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_packet_rate_limit_rule',
            self.target)

    def test_delete_policy_packet_rate_limit_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_packet_rate_limit_rule',
            self.target)


class SystemAdminQosDSCPMarkingRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_get_policy_dscp_marking_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_policy_dscp_marking_rule',
                self.target)

            # And the same for aliases
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_alias_dscp_marking_rule',
                self.target)

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_policy_dscp_marking_rule',
                self.alt_target)

            # And the same for aliases
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_alias_dscp_marking_rule',
                self.alt_target)

    def test_create_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_dscp_marking_rule',
            self.alt_target)

    def test_update_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_dscp_marking_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_alias_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_alias_dscp_marking_rule',
            self.alt_target)

    def test_delete_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_dscp_marking_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_alias_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_alias_dscp_marking_rule',
            self.alt_target)


class SystemMemberQosDSCPMarkingRuleTests(SystemAdminQosDSCPMarkingRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderQosDSCPMarkingRuleTests(SystemMemberQosDSCPMarkingRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminQosDSCPMarkingRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_get_policy_dscp_marking_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_dscp_marking_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_dscp_marking_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_dscp_marking_rule',
                               self.alt_target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_dscp_marking_rule',
                               self.alt_target))

    def test_create_policy_dscp_marking_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_policy_dscp_marking_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_policy_dscp_marking_rule',
                           self.alt_target))

    def test_update_policy_dscp_marking_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_policy_dscp_marking_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_policy_dscp_marking_rule',
                           self.alt_target))

        # And the same for aliases
        self.assertTrue(
            policy.enforce(self.context,
                           'update_alias_dscp_marking_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_alias_dscp_marking_rule',
                           self.alt_target))

    def test_delete_policy_dscp_marking_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_policy_dscp_marking_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_policy_dscp_marking_rule',
                           self.alt_target))

        # And the same for aliases
        self.assertTrue(
            policy.enforce(self.context,
                           'update_alias_dscp_marking_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_alias_dscp_marking_rule',
                           self.alt_target))


class ProjectManagerQosDSCPMarkingRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_get_policy_dscp_marking_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_dscp_marking_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_dscp_marking_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_dscp_marking_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_alias_dscp_marking_rule',
                self.alt_target)

    def test_create_policy_dscp_marking_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'create_policy_dscp_marking_rule',
                               self.target))
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_policy_dscp_marking_rule',
                self.alt_target)

    def test_update_policy_dscp_marking_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'update_policy_dscp_marking_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'update_alias_dscp_marking_rule',
                               self.target))
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_policy_dscp_marking_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_alias_dscp_marking_rule',
                self.alt_target)

    def test_delete_policy_dscp_marking_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_policy_dscp_marking_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_alias_dscp_marking_rule',
                               self.target))
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_policy_dscp_marking_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_alias_dscp_marking_rule',
                self.alt_target)


class ProjectMemberQosDSCPMarkingRuleTests(
        ProjectManagerQosDSCPMarkingRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx

    def test_create_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_dscp_marking_rule',
            self.alt_target)

    def test_update_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_dscp_marking_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_dscp_marking_rule',
            self.alt_target)

    def test_delete_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_dscp_marking_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_dscp_marking_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_dscp_marking_rule',
            self.alt_target)


class ProjectReaderQosDSCPMarkingRuleTests(
        ProjectMemberQosDSCPMarkingRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx


class ServiceRoleQosDSCPMarkingRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_get_policy_dscp_marking_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_dscp_marking_rule',
                self.target)

            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_alias_dscp_marking_rule',
                self.target)

    def test_create_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_dscp_marking_rule',
            self.target)

    def test_update_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_dscp_marking_rule',
            self.target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_dscp_marking_rule',
            self.target)

    def test_delete_policy_dscp_marking_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_dscp_marking_rule',
            self.target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_dscp_marking_rule',
            self.target)


class SystemAdminQosMinimumBandwidthRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_get_policy_minimum_bandwidth_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_policy_minimum_bandwidth_rule',
                self.target)
            # And the same for aliases
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_alias_minimum_bandwidth_rule',
                self.target)

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_policy_minimum_bandwidth_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_alias_minimum_bandwidth_rule',
                self.alt_target)

    def test_create_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_minimum_bandwidth_rule',
            self.alt_target)

    def test_update_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_minimum_bandwidth_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_alias_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_alias_minimum_bandwidth_rule',
            self.alt_target)

    def test_delete_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_minimum_bandwidth_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_alias_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_alias_minimum_bandwidth_rule',
            self.alt_target)


class SystemMemberQosMinimumBandwidthRuleTests(
        SystemAdminQosMinimumBandwidthRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderQosMinimumBandwidthRuleTests(
        SystemMemberQosMinimumBandwidthRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminQosMinimumBandwidthRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_get_policy_minimum_bandwidth_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(
                    self.context, 'get_policy_minimum_bandwidth_rule',
                    self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(
                    self.context, 'get_alias_minimum_bandwidth_rule',
                    self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertTrue(
                policy.enforce(
                    self.context, 'get_policy_minimum_bandwidth_rule',
                    self.alt_target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(
                    self.context, 'get_alias_minimum_bandwidth_rule',
                    self.alt_target))

    def test_create_policy_minimum_bandwidth_rule(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_policy_minimum_bandwidth_rule',
                self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_policy_minimum_bandwidth_rule',
                self.alt_target))

    def test_update_policy_minimum_bandwidth_rule(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_policy_minimum_bandwidth_rule',
                self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_policy_minimum_bandwidth_rule',
                self.alt_target))

        # And the same for aliases
        self.assertTrue(
            policy.enforce(
                self.context, 'update_alias_minimum_bandwidth_rule',
                self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_alias_minimum_bandwidth_rule',
                self.alt_target))

    def test_delete_policy_minimum_bandwidth_rule(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_policy_minimum_bandwidth_rule',
                self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_policy_minimum_bandwidth_rule',
                self.alt_target))

        # And the same for aliases
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_alias_minimum_bandwidth_rule',
                self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_alias_minimum_bandwidth_rule',
                self.alt_target))


class ProjectManagerQosMinimumBandwidthRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_get_policy_minimum_bandwidth_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(
                    self.context, 'get_policy_minimum_bandwidth_rule',
                    self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(
                    self.context, 'get_alias_minimum_bandwidth_rule',
                    self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_minimum_bandwidth_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_alias_minimum_bandwidth_rule',
                self.alt_target)

    def test_create_policy_minimum_bandwidth_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(
                    self.context, 'create_policy_minimum_bandwidth_rule',
                    self.target))
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_policy_minimum_bandwidth_rule',
                self.alt_target)

    def test_update_policy_minimum_bandwidth_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(
                    self.context, 'update_policy_minimum_bandwidth_rule',
                    self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(
                    self.context, 'update_alias_minimum_bandwidth_rule',
                    self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_policy_minimum_bandwidth_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_alias_minimum_bandwidth_rule',
                self.alt_target)

    def test_delete_policy_minimum_bandwidth_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(
                    self.context, 'delete_policy_minimum_bandwidth_rule',
                    self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(
                    self.context, 'delete_alias_minimum_bandwidth_rule',
                    self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_policy_minimum_bandwidth_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_alias_minimum_bandwidth_rule',
                self.alt_target)


class ProjectMemberQosMinimumBandwidthRuleTests(
        ProjectManagerQosMinimumBandwidthRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx

    def test_create_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_minimum_bandwidth_rule',
            self.alt_target)

    def test_update_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_minimum_bandwidth_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_minimum_bandwidth_rule',
            self.alt_target)

    def test_delete_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_minimum_bandwidth_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_minimum_bandwidth_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_minimum_bandwidth_rule',
            self.alt_target)


class ProjectReaderQosMinimumBandwidthRuleTests(
        ProjectMemberQosMinimumBandwidthRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx


class ServiceRoleQosMinimumBandwidthRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_get_policy_minimum_bandwidth_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_minimum_bandwidth_rule',
                self.target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_alias_minimum_bandwidth_rule',
                self.target)

    def test_create_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_minimum_bandwidth_rule',
            self.target)

    def test_update_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_minimum_bandwidth_rule',
            self.target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_minimum_bandwidth_rule',
            self.target)

    def test_delete_policy_minimum_bandwidth_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_minimum_bandwidth_rule',
            self.target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_minimum_bandwidth_rule',
            self.target)


class SystemAdminQosMinimumPacketRateRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_get_policy_minimum_packet_rate_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_policy_minimum_packet_rate_rule',
                self.target)
            # And the same for aliases
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_alias_minimum_packet_rate_rule',
                self.target)

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_policy_minimum_packet_rate_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.InvalidScope,
                policy.enforce,
                self.context, 'get_alias_minimum_packet_rate_rule',
                self.alt_target)

    def test_create_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'create_policy_minimum_packet_rate_rule',
            self.alt_target)

    def test_update_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'update_policy_minimum_packet_rate_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_alias_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_alias_minimum_packet_rate_rule',
            self.alt_target)

    def test_delete_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_policy_minimum_packet_rate_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_alias_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'delete_alias_minimum_packet_rate_rule',
            self.alt_target)


class SystemMemberQosMinimumPacketRateRuleTests(
        SystemAdminQosMinimumPacketRateRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderQosMinimumPacketRateRuleTests(
        SystemMemberQosMinimumPacketRateRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminQosMinimumPacketRateRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_get_policy_minimum_packet_rate_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_minimum_packet_rate_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_minimum_packet_rate_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_minimum_packet_rate_rule',
                               self.alt_target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_minimum_packet_rate_rule',
                               self.alt_target))

    def test_create_policy_minimum_packet_rate_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'create_policy_minimum_packet_rate_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'create_policy_minimum_packet_rate_rule',
                           self.alt_target))

    def test_update_policy_minimum_packet_rate_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'update_policy_minimum_packet_rate_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_policy_minimum_packet_rate_rule',
                           self.alt_target))

        # And the same for aliases
        self.assertTrue(
            policy.enforce(self.context,
                           'update_alias_minimum_packet_rate_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'update_alias_minimum_packet_rate_rule',
                           self.alt_target))

    def test_delete_policy_minimum_packet_rate_rule(self):
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_policy_minimum_packet_rate_rule',
                           self.target))
        self.assertTrue(
            policy.enforce(self.context,
                           'delete_policy_minimum_packet_rate_rule',
                           self.alt_target))


class ProjectManagerQosMinimumPacketRateRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_get_policy_minimum_packet_rate_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'get_policy_minimum_packet_rate_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'get_alias_minimum_packet_rate_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_minimum_packet_rate_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_alias_minimum_packet_rate_rule',
                self.alt_target)

    def test_create_policy_minimum_packet_rate_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'create_policy_minimum_packet_rate_rule',
                               self.target))
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'create_policy_minimum_packet_rate_rule',
                self.alt_target)

    def test_update_policy_minimum_packet_rate_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'update_policy_minimum_packet_rate_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'update_alias_minimum_packet_rate_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_policy_minimum_packet_rate_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'update_alias_minimum_packet_rate_rule',
                self.alt_target)

    def test_delete_policy_minimum_packet_rate_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_policy_minimum_packet_rate_rule',
                               self.target))
            # And the same for aliases
            self.assertTrue(
                policy.enforce(self.context,
                               'delete_alias_minimum_packet_rate_rule',
                               self.target))

        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.alt_qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_policy_minimum_packet_rate_rule',
                self.alt_target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'delete_alias_minimum_packet_rate_rule',
                self.alt_target)


class ProjectMemberQosMinimumPacketRateRuleTests(
        ProjectManagerQosMinimumPacketRateRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx

    def test_create_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_minimum_packet_rate_rule',
            self.alt_target)

    def test_update_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_minimum_packet_rate_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_alias_minimum_packet_rate_rule',
            self.alt_target)

    def test_delete_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_minimum_packet_rate_rule',
            self.alt_target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_minimum_packet_rate_rule',
            self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_minimum_packet_rate_rule',
            self.alt_target)


class ProjectReaderQosMinimumPacketRateRuleTests(
        ProjectMemberQosMinimumPacketRateRuleTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_reader_ctx


class ServiceRoleQosMinimumPacketRateRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_get_policy_minimum_packet_rate_rule(self):
        with mock.patch.object(self.plugin_mock, "get_policy",
                               return_value=self.qos_policy):
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_policy_minimum_packet_rate_rule',
                self.target)
            # And the same for aliases
            self.assertRaises(
                base_policy.PolicyNotAuthorized,
                policy.enforce,
                self.context, 'get_alias_minimum_packet_rate_rule',
                self.target)

    def test_create_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'create_policy_minimum_packet_rate_rule',
            self.target)

    def test_update_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'update_policy_minimum_packet_rate_rule',
            self.target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_alias_minimum_packet_rate_rule',
            self.target)

    def test_delete_policy_minimum_packet_rate_rule(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_policy_minimum_packet_rate_rule',
            self.target)

        # And the same for aliases
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'delete_alias_minimum_packet_rate_rule',
            self.target)
