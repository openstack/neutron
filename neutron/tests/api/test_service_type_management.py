#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest import test

from neutron.tests.api import base


class ServiceTypeManagementTest(base.BaseNetworkTest):

    @classmethod
    @test.requires_ext(extension="service-type", service="network")
    def resource_setup(cls):
        super(ServiceTypeManagementTest, cls).resource_setup()

    @test.attr(type='smoke')
    @test.idempotent_id('2cbbeea9-f010-40f6-8df5-4eaa0c918ea6')
    def test_service_provider_list(self):
        body = self.client.list_service_providers()
        self.assertIsInstance(body['service_providers'], list)
