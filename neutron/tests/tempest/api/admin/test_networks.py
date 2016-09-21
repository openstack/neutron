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

from oslo_utils import uuidutils
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron.tests.tempest.api import base


class NetworksTestAdmin(base.BaseAdminNetworkTest):

    @test.idempotent_id('d3c76044-d067-4cb0-ae47-8cdd875c7f67')
    @test.requires_ext(extension="project-id", service="network")
    def test_admin_create_network_keystone_v3(self):
        project_id = self.client.tenant_id  # non-admin

        name = 'admin-created-with-project_id'
        new_net = self.create_network_keystone_v3(name, project_id,
            client=self.admin_client)
        self.assertEqual(name, new_net['name'])
        self.assertEqual(project_id, new_net['project_id'])
        self.assertEqual(project_id, new_net['tenant_id'])

        body = self.client.list_networks(id=new_net['id'])
        lookup_net = body['networks'][0]
        self.assertEqual(name, lookup_net['name'])
        self.assertEqual(project_id, lookup_net['project_id'])
        self.assertEqual(project_id, lookup_net['tenant_id'])

    @test.idempotent_id('8d21aaca-4364-4eb9-8b79-44b4fff6373b')
    @test.requires_ext(extension="project-id", service="network")
    def test_admin_create_network_keystone_v3_and_tenant(self):
        project_id = self.client.tenant_id  # non-admin

        name = 'created-with-project-and-tenant'
        new_net = self.create_network_keystone_v3(
            name, project_id, tenant_id=project_id, client=self.admin_client)
        self.assertEqual(name, new_net['name'])
        self.assertEqual(project_id, new_net['project_id'])
        self.assertEqual(project_id, new_net['tenant_id'])

        body = self.client.list_networks(id=new_net['id'])
        lookup_net = body['networks'][0]
        self.assertEqual(name, lookup_net['name'])
        self.assertEqual(project_id, lookup_net['project_id'])
        self.assertEqual(project_id, lookup_net['tenant_id'])

    @test.idempotent_id('08b92179-669d-45ee-8233-ef6611190809')
    @test.requires_ext(extension="project-id", service="network")
    def test_admin_create_network_keystone_v3_and_other_tenant(self):
        project_id = self.client.tenant_id  # non-admin
        other_tenant = uuidutils.generate_uuid()

        name = 'created-with-project-and-other-tenant'
        e = self.assertRaises(lib_exc.BadRequest,
                              self.create_network_keystone_v3, name,
                              project_id, tenant_id=other_tenant,
                              client=self.admin_client)
        expected_message = "'project_id' and 'tenant_id' do not match"
        self.assertEqual(expected_message, e.resp_body['message'])
