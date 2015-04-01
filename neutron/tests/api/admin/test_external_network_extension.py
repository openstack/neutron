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

from tempest_lib.common.utils import data_utils

from neutron.tests.api import base
from neutron.tests.tempest import test


class ExternalNetworksTestJSON(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(ExternalNetworksTestJSON, cls).resource_setup()
        cls.network = cls.create_network()

    def _create_network(self, external=True):
        post_body = {'name': data_utils.rand_name('network-')}
        if external:
            post_body['router:external'] = external
        body = self.admin_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(self.admin_client.delete_network, network['id'])
        return network

    @test.idempotent_id('462be770-b310-4df9-9c42-773217e4c8b1')
    def test_create_external_network(self):
        # Create a network as an admin user specifying the
        # external network extension attribute
        ext_network = self._create_network()
        # Verifies router:external parameter
        self.assertIsNotNone(ext_network['id'])
        self.assertTrue(ext_network['router:external'])

    @test.idempotent_id('4db5417a-e11c-474d-a361-af00ebef57c5')
    def test_update_external_network(self):
        # Update a network as an admin user specifying the
        # external network extension attribute
        network = self._create_network(external=False)
        self.assertFalse(network.get('router:external', False))
        update_body = {'router:external': True}
        body = self.admin_client.update_network(network['id'],
                                                **update_body)
        updated_network = body['network']
        # Verify that router:external parameter was updated
        self.assertTrue(updated_network['router:external'])

    @test.idempotent_id('39be4c9b-a57e-4ff9-b7c7-b218e209dfcc')
    def test_list_external_networks(self):
        # Create external_net
        external_network = self._create_network()
        # List networks as a normal user and confirm the external
        # network extension attribute is returned for those networks
        # that were created as external
        body = self.client.list_networks()
        networks_list = [net['id'] for net in body['networks']]
        self.assertIn(external_network['id'], networks_list)
        self.assertIn(self.network['id'], networks_list)
        for net in body['networks']:
            if net['id'] == self.network['id']:
                self.assertFalse(net['router:external'])
            elif net['id'] == external_network['id']:
                self.assertTrue(net['router:external'])

    @test.idempotent_id('2ac50ab2-7ebd-4e27-b3ce-a9e399faaea2')
    def test_show_external_networks_attribute(self):
        # Create external_net
        external_network = self._create_network()
        # Show an external network as a normal user and confirm the
        # external network extension attribute is returned.
        body = self.client.show_network(external_network['id'])
        show_ext_net = body['network']
        self.assertEqual(external_network['name'], show_ext_net['name'])
        self.assertEqual(external_network['id'], show_ext_net['id'])
        self.assertTrue(show_ext_net['router:external'])
        body = self.client.show_network(self.network['id'])
        show_net = body['network']
        # Verify with show that router:external is False for network
        self.assertEqual(self.network['name'], show_net['name'])
        self.assertEqual(self.network['id'], show_net['id'])
        self.assertFalse(show_net['router:external'])

    @test.idempotent_id('82068503-2cf2-4ed4-b3be-ecb89432e4bb')
    def test_delete_external_networks_with_floating_ip(self):
        """Verifies external network can be deleted while still holding
        (unassociated) floating IPs

        """
        # Set cls.client to admin to use base.create_subnet()
        client = self.admin_client
        body = client.create_network(**{'router:external': True})
        external_network = body['network']
        self.addCleanup(self._try_delete_resource,
                        client.delete_network,
                        external_network['id'])
        subnet = self.create_subnet(external_network, client=client,
                                    enable_dhcp=False)
        body = client.create_floatingip(
            floating_network_id=external_network['id'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self._try_delete_resource,
                        client.delete_floatingip,
                        created_floating_ip['id'])
        floatingip_list = client.list_floatingips(
            network=external_network['id'])
        self.assertIn(created_floating_ip['id'],
                      (f['id'] for f in floatingip_list['floatingips']))
        client.delete_network(external_network['id'])
        # Verifies floating ip is deleted
        floatingip_list = client.list_floatingips()
        self.assertNotIn(created_floating_ip['id'],
                         (f['id'] for f in floatingip_list['floatingips']))
        # Verifies subnet is deleted
        subnet_list = client.list_subnets()
        self.assertNotIn(subnet['id'],
                         (s['id'] for s in subnet_list))
        # Removes subnet from the cleanup list
        self.subnets.remove(subnet)
