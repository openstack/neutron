# All Rights Reserved.
#
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

from tempest.lib import decorators

from neutron.tests.tempest.api import base_security_groups as base


class SecGroupAdminTest(base.BaseSecGroupTest):
    required_extensions = ['security-group']
    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(SecGroupAdminTest, cls).setup_clients()
        cls.admin_client = cls.os_admin.network_client
        cls.identity_admin_client = cls.os_admin.projects_client

    @decorators.idempotent_id('44f1e1c4-af10-4aa0-972f-87c1c8fa25cc')
    def test_security_group_recreated_on_port_update(self):
        network = self.create_network()
        self.create_subnet(network)
        port = self.create_port(network, security_groups=[])
        for sg in self.client.list_security_groups()['security_groups']:
            if sg['name'] == 'default':
                self.admin_client.delete_security_group(sg['id'])
        self.update_port(port, name='update')
        names = [
            sg['name']
            for sg in self.client.list_security_groups()['security_groups']
        ]
        self.assertIn('default', names)
