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
        super(QosPolicyAPITestCase, self).setUp()
        self.target = {'project_id': self.project_id}
        self.alt_target = {'project_id': self.alt_project_id}


class SystemAdminQosPolicyTests(QosPolicyAPITestCase):

    def setUp(self):
        super(SystemAdminQosPolicyTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_get_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_policy', self.alt_target)

    def test_create_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_policy', self.alt_target)

    def test_update_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_policy', self.alt_target)

    def test_delete_policy(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_policy', self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_policy', self.alt_target)


class SystemMemberQosPolicyTests(SystemAdminQosPolicyTests):

    def setUp(self):
        super(SystemMemberQosPolicyTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderQosPolicyTests(SystemMemberQosPolicyTests):

    def setUp(self):
        super(SystemReaderQosPolicyTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminQosPolicyTests(QosPolicyAPITestCase):

    def setUp(self):
        super(AdminQosPolicyTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_get_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_policy', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'get_policy', self.alt_target))

    def test_create_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'create_policy', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'create_policy', self.alt_target))

    def test_update_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'update_policy', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'update_policy', self.alt_target))

    def test_delete_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'delete_policy', self.target))
        self.assertTrue(
            policy.enforce(self.context, 'delete_policy', self.alt_target))


class ProjectMemberQosPolicyTests(AdminQosPolicyTests):

    def setUp(self):
        super(ProjectMemberQosPolicyTests, self).setUp()
        self.context = self.project_member_ctx

    def test_get_policy(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_policy', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_policy', self.alt_target)

    def test_create_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_policy', self.alt_target)

    def test_update_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_policy', self.alt_target)

    def test_delete_policy(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy', self.target)
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_policy', self.alt_target)


class ProjectReaderQosPolicyTests(ProjectMemberQosPolicyTests):

    def setUp(self):
        super(ProjectReaderQosPolicyTests, self).setUp()
        self.context = self.project_reader_ctx


class QosRuleTypeAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(QosRuleTypeAPITestCase, self).setUp()
        self.target = {}


class SystemAdminQosRuleTypeTests(QosRuleTypeAPITestCase):

    def setUp(self):
        super(SystemAdminQosRuleTypeTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_get_rule_type(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_rule_type', self.target)


class SystemMemberQosRuleTypeTests(SystemAdminQosRuleTypeTests):

    def setUp(self):
        super(SystemMemberQosRuleTypeTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderQosRuleTypeTests(SystemMemberQosRuleTypeTests):

    def setUp(self):
        super(SystemReaderQosRuleTypeTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminQosRuleTypeTests(QosRuleTypeAPITestCase):

    def setUp(self):
        super(AdminQosRuleTypeTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_get_rule_type(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_rule_type', self.target))


class ProjectMemberQosRuleTypeTests(AdminQosRuleTypeTests):

    def setUp(self):
        super(ProjectMemberQosRuleTypeTests, self).setUp()
        self.context = self.project_member_ctx


class ProjectReaderQosRuleTypeTests(ProjectMemberQosRuleTypeTests):

    def setUp(self):
        super(ProjectReaderQosRuleTypeTests, self).setUp()
        self.context = self.project_reader_ctx


class QosRulesAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(QosRulesAPITestCase, self).setUp()
        self.qos_policy = {
            'id': uuidutils.generate_uuid(),
            'tenant_id': self.project_id,
            'project_id': self.project_id}
        self.alt_qos_policy = {
            'id': uuidutils.generate_uuid(),
            'tenant_id': self.alt_project_id,
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
        super(SystemAdminQosBandwidthLimitRuleTests, self).setUp()
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
        super(SystemMemberQosBandwidthLimitRuleTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderQosBandwidthLimitRuleTests(
        SystemMemberQosBandwidthLimitRuleTests):

    def setUp(self):
        super(SystemReaderQosBandwidthLimitRuleTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminQosBandwidthLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super(AdminQosBandwidthLimitRuleTests, self).setUp()
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


class ProjectMemberQosBandwidthLimitRuleTests(
        AdminQosBandwidthLimitRuleTests):

    def setUp(self):
        super(ProjectMemberQosBandwidthLimitRuleTests, self).setUp()
        self.context = self.project_member_ctx

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
        super(ProjectReaderQosBandwidthLimitRuleTests, self).setUp()
        self.context = self.project_reader_ctx


class SystemAdminQosPacketRateLimitRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super(SystemAdminQosPacketRateLimitRuleTests, self).setUp()
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
        super(AdminQosPacketRateLimitRuleTests, self).setUp()
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


class ProjectMemberQosPacketRateLimitRuleTests(
        AdminQosPacketRateLimitRuleTests):

    def setUp(self):
        super(ProjectMemberQosPacketRateLimitRuleTests, self).setUp()
        self.context = self.project_member_ctx

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
        super(ProjectReaderQosPacketRateLimitRuleTests, self).setUp()
        self.context = self.project_reader_ctx


class SystemAdminQosDSCPMarkingRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super(SystemAdminQosDSCPMarkingRuleTests, self).setUp()
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
        super(SystemMemberQosDSCPMarkingRuleTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderQosDSCPMarkingRuleTests(SystemMemberQosDSCPMarkingRuleTests):

    def setUp(self):
        super(SystemReaderQosDSCPMarkingRuleTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminQosDSCPMarkingRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super(AdminQosDSCPMarkingRuleTests, self).setUp()
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


class ProjectMemberQosDSCPMarkingRuleTests(
        AdminQosDSCPMarkingRuleTests):

    def setUp(self):
        super(ProjectMemberQosDSCPMarkingRuleTests, self).setUp()
        self.context = self.project_member_ctx

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
        super(ProjectReaderQosDSCPMarkingRuleTests, self).setUp()
        self.context = self.project_reader_ctx


class SystemAdminQosMinimumBandwidthRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super(SystemAdminQosMinimumBandwidthRuleTests, self).setUp()
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
        super(SystemMemberQosMinimumBandwidthRuleTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderQosMinimumBandwidthRuleTests(
        SystemMemberQosMinimumBandwidthRuleTests):

    def setUp(self):
        super(SystemReaderQosMinimumBandwidthRuleTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminQosMinimumBandwidthRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super(AdminQosMinimumBandwidthRuleTests, self).setUp()
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


class ProjectMemberQosMinimumBandwidthRuleTests(
        AdminQosMinimumBandwidthRuleTests):

    def setUp(self):
        super(ProjectMemberQosMinimumBandwidthRuleTests, self).setUp()
        self.context = self.project_member_ctx

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
        super(ProjectReaderQosMinimumBandwidthRuleTests, self).setUp()
        self.context = self.project_reader_ctx


class SystemAdminQosMinimumPacketRateRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super(SystemAdminQosMinimumPacketRateRuleTests, self).setUp()
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
        super(SystemMemberQosMinimumPacketRateRuleTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderQosMinimumPacketRateRuleTests(
        SystemMemberQosMinimumPacketRateRuleTests):

    def setUp(self):
        super(SystemReaderQosMinimumPacketRateRuleTests, self).setUp()
        self.context = self.system_reader_ctx


class AdminQosMinimumPacketRateRuleTests(QosRulesAPITestCase):

    def setUp(self):
        super(AdminQosMinimumPacketRateRuleTests, self).setUp()
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


class ProjectMemberQosMinimumPacketRateRuleTests(
        AdminQosMinimumPacketRateRuleTests):

    def setUp(self):
        super(ProjectMemberQosMinimumPacketRateRuleTests, self).setUp()
        self.context = self.project_member_ctx

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
        super(ProjectReaderQosMinimumPacketRateRuleTests, self).setUp()
        self.context = self.project_reader_ctx
