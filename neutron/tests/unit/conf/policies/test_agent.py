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


class AgentAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(AgentAPITestCase, self).setUp()
        self.target = {}


class SystemAdminTests(AgentAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_get_agent(self):
        self.assertTrue(
            policy.enforce(self.context, "get_agent", self.target))

    def test_update_agent(self):
        self.assertTrue(
            policy.enforce(self.context, "update_agent", self.target))

    def test_delete_agent(self):
        self.assertTrue(
            policy.enforce(self.context, "delete_agent", self.target))

    def test_add_network_to_dhcp_agent(self):
        self.assertTrue(
            policy.enforce(self.context,
                           "create_dhcp-network",
                           self.target))

    def test_get_networks_on_dhcp_agent(self):
        self.assertTrue(
            policy.enforce(self.context,
                           "get_dhcp-networks", self.target))

    def test_delete_network_from_dhcp_agent(self):
        self.assertTrue(
            policy.enforce(self.context,
                           "delete_dhcp-network",
                           self.target))

    def test_add_router_to_l3_agent(self):
        self.assertTrue(
            policy.enforce(self.context,
                           "create_l3-router",
                           self.target))

    def test_get_routers_on_l3_agent(self):
        self.assertTrue(
            policy.enforce(self.context,
                           "get_l3-routers", self.target))

    def test_delete_router_from_l3_agent(self):
        self.assertTrue(
            policy.enforce(self.context,
                           "delete_l3-router",
                           self.target))

    def test_get_dhcp_agents_hosting_network(self):
        self.assertTrue(
            policy.enforce(self.context,
                           "get_dhcp-agents", self.target))

    def test_get_l3_agents_hosting_router(self):
        self.assertTrue(
            policy.enforce(self.context,
                           "get_l3-agents", self.target))


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx

    def test_update_agent(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "update_agent", self.target)

    def test_delete_agent(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "delete_agent", self.target)

    def test_add_network_to_dhcp_agent(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "create_dhcp-network", self.target)

    def test_delete_network_from_dhcp_agent(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "delete_dhcp-network", self.target)

    def test_add_router_to_l3_agent(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "create_l3-router", self.target)

    def test_delete_router_from_l3_agent(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, "delete_l3-router", self.target)


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_reader_ctx


class ProjectAdminTests(AgentAPITestCase):

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_get_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "get_agent", self.target)

    def test_update_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "update_agent", self.target)

    def test_delete_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "delete_agent", self.target)

    def test_add_network_to_dhcp_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "create_dhcp-network", self.target)

    def test_networks_on_dhcp_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "get_dhcp-networks", self.target)

    def test_delete_network_from_dhcp_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "delete_dhcp-network", self.target)

    def test_add_router_to_l3_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "create_l3-router", self.target)

    def test_get_routers_on_l3_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "get_l3-routers", self.target)

    def test_delete_router_from_l3_agent(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "delete_l3-router", self.target)

    def test_get_dhcp_agents_hosting_network(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "get_dhcp-agents", self.target)

    def test_get_l3_agents_hosting_router(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, "get_l3-agents", self.target)


class ProjectMemberTests(ProjectAdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx
