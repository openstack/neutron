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


class NetworkIPAvailabilityAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(NetworkIPAvailabilityAPITestCase, self).setUp()
        self.target = {}


class SystemAdminTests(NetworkIPAvailabilityAPITestCase):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.context = self.system_admin_ctx

    def test_get_network_ip_availability(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce,
            self.context, 'get_network_ip_availability', self.target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.context = self.system_member_ctx


class AdminTests(NetworkIPAvailabilityAPITestCase):

    def setUp(self):
        super(AdminTests, self).setUp()
        self.context = self.project_admin_ctx

    def test_get_network_ip_availability(self):
        self.assertTrue(
            policy.enforce(self.context, 'get_network_ip_availability',
                           self.target))


class ProjectMemberTests(AdminTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.context = self.project_member_ctx

    def test_get_network_ip_availability(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.context, 'get_network_ip_availability', self.target)


class ProjectReaderTests(ProjectMemberTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.context = self.project_reader_ctx
