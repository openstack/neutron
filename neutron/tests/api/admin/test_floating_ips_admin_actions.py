# Copyright 2014 OpenStack Foundation
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

from tempest_lib.common.utils import data_utils

from neutron.tests.api import base
from neutron.tests.api import clients
from neutron.tests.tempest import config
from neutron.tests.tempest import test

CONF = config.CONF


class FloatingIPAdminTestJSON(base.BaseAdminNetworkTest):

    force_tenant_isolation = True

    @classmethod
    def resource_setup(cls):
        super(FloatingIPAdminTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        cls.floating_ip = cls.create_floatingip(cls.ext_net_id)
        cls.alt_manager = clients.Manager(cls.isolated_creds.get_alt_creds())
        cls.alt_client = cls.alt_manager.network_client
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = cls.create_port(cls.network)

    @test.attr(type='smoke')
    @test.idempotent_id('64f2100b-5471-4ded-b46c-ddeeeb4f231b')
    def test_list_floating_ips_from_admin_and_nonadmin(self):
        # Create floating ip from admin user
        floating_ip_admin = self.admin_client.create_floatingip(
            floating_network_id=self.ext_net_id)
        self.addCleanup(self.admin_client.delete_floatingip,
                        floating_ip_admin['floatingip']['id'])
        # Create floating ip from alt user
        body = self.alt_client.create_floatingip(
            floating_network_id=self.ext_net_id)
        floating_ip_alt = body['floatingip']
        self.addCleanup(self.alt_client.delete_floatingip,
                        floating_ip_alt['id'])
        # List floating ips from admin
        body = self.admin_client.list_floatingips()
        floating_ip_ids_admin = [f['id'] for f in body['floatingips']]
        # Check that admin sees all floating ips
        self.assertIn(self.floating_ip['id'], floating_ip_ids_admin)
        self.assertIn(floating_ip_admin['floatingip']['id'],
                      floating_ip_ids_admin)
        self.assertIn(floating_ip_alt['id'], floating_ip_ids_admin)
        # List floating ips from nonadmin
        body = self.client.list_floatingips()
        floating_ip_ids = [f['id'] for f in body['floatingips']]
        # Check that nonadmin user doesn't see floating ip created from admin
        # and floating ip that is created in another tenant (alt user)
        self.assertIn(self.floating_ip['id'], floating_ip_ids)
        self.assertNotIn(floating_ip_admin['floatingip']['id'],
                         floating_ip_ids)
        self.assertNotIn(floating_ip_alt['id'], floating_ip_ids)

    @test.attr(type='smoke')
    @test.idempotent_id('32727cc3-abe2-4485-a16e-48f2d54c14f2')
    def test_create_list_show_floating_ip_with_tenant_id_by_admin(self):
        # Creates a floating IP
        body = self.admin_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            tenant_id=self.network['tenant_id'],
            port_id=self.port['id'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['tenant_id'])
        self.assertIsNotNone(created_floating_ip['floating_ip_address'])
        self.assertEqual(created_floating_ip['port_id'], self.port['id'])
        self.assertEqual(created_floating_ip['floating_network_id'],
                         self.ext_net_id)
        port = self.port['fixed_ips']
        self.assertEqual(created_floating_ip['fixed_ip_address'],
                         port[0]['ip_address'])
        # Verifies the details of a floating_ip
        floating_ip = self.admin_client.show_floatingip(
            created_floating_ip['id'])
        shown_floating_ip = floating_ip['floatingip']
        self.assertEqual(shown_floating_ip['id'], created_floating_ip['id'])
        self.assertEqual(shown_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertEqual(shown_floating_ip['tenant_id'],
                         self.network['tenant_id'])
        self.assertEqual(shown_floating_ip['floating_ip_address'],
                         created_floating_ip['floating_ip_address'])
        self.assertEqual(shown_floating_ip['port_id'], self.port['id'])
        # Verify the floating ip exists in the list of all floating_ips
        floating_ips = self.admin_client.list_floatingips()
        floatingip_id_list = [f['id'] for f in floating_ips['floatingips']]
        self.assertIn(created_floating_ip['id'], floatingip_id_list)
