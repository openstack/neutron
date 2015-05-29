# Copyright 2015 Hewlett-Packard Development Company, L.P.dsvsv
# Copyright 2015 OpenStack Foundation
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

from tempest_lib import exceptions as lib_exc
import testtools

from neutron.tests.api import base
from neutron.tests.tempest import config
from neutron.tests.tempest import test
from tempest_lib.common.utils import data_utils

CONF = config.CONF


class SharedNetworksTest(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(SharedNetworksTest, cls).resource_setup()
        cls.shared_network = cls.create_shared_network()

    @test.idempotent_id('6661d219-b96d-4597-ad10-55766ce4abf7')
    def test_create_update_shared_network(self):
        shared_network = self.create_shared_network()
        net_id = shared_network['id']
        self.assertEqual('ACTIVE', shared_network['status'])
        self.assertIsNotNone(shared_network['id'])
        self.assertTrue(self.shared_network['shared'])
        new_name = "New_shared_network"
        body = self.admin_client.update_network(net_id, name=new_name,
                                                admin_state_up=False,
                                                shared=False)
        updated_net = body['network']
        self.assertEqual(new_name, updated_net['name'])
        self.assertFalse(updated_net['shared'])
        self.assertFalse(updated_net['admin_state_up'])

    @test.idempotent_id('9c31fabb-0181-464f-9ace-95144fe9ca77')
    def test_create_port_shared_network_as_non_admin_tenant(self):
        # create a port as non admin
        body = self.client.create_port(network_id=self.shared_network['id'])
        port = body['port']
        self.addCleanup(self.admin_client.delete_port, port['id'])
        # verify the tenant id of admin network and non admin port
        self.assertNotEqual(self.shared_network['tenant_id'],
                            port['tenant_id'])

    @test.idempotent_id('3e39c4a6-9caf-4710-88f1-d20073c6dd76')
    def test_create_bulk_shared_network(self):
        # Creates 2 networks in one request
        net_nm = [data_utils.rand_name('network'),
                  data_utils.rand_name('network')]
        body = self.admin_client.create_bulk_network(net_nm, shared=True)
        created_networks = body['networks']
        for net in created_networks:
            self.addCleanup(self.admin_client.delete_network, net['id'])
            self.assertIsNotNone(net['id'])
            self.assertTrue(net['shared'])

    def _list_shared_networks(self, user):
        body = user.list_networks(shared=True)
        networks_list = [net['id'] for net in body['networks']]
        self.assertIn(self.shared_network['id'], networks_list)
        self.assertTrue(self.shared_network['shared'])

    @test.idempotent_id('a064a9fd-e02f-474a-8159-f828cd636a28')
    def test_list_shared_networks(self):
        # List the shared networks and confirm that
        # shared network extension attribute is returned for those networks
        # that are created as shared
        self._list_shared_networks(self.admin_client)
        self._list_shared_networks(self.client)

    def _show_shared_network(self, user):
        body = user.show_network(self.shared_network['id'])
        show_shared_net = body['network']
        self.assertEqual(self.shared_network['name'], show_shared_net['name'])
        self.assertEqual(self.shared_network['id'], show_shared_net['id'])
        self.assertTrue(show_shared_net['shared'])

    @test.idempotent_id('e03c92a2-638d-4bfa-b50a-b1f66f087e58')
    def test_show_shared_networks_attribute(self):
        # Show a shared network and confirm that
        # shared network extension attribute is returned.
        self._show_shared_network(self.admin_client)
        self._show_shared_network(self.client)


class AllowedAddressPairSharedNetworkTest(base.BaseAdminNetworkTest):
    allowed_address_pairs = [{'ip_address': '1.1.1.1'}]

    @classmethod
    def skip_checks(cls):
        super(AllowedAddressPairSharedNetworkTest, cls).skip_checks()
        if not test.is_extension_enabled('allowed-address-pairs', 'network'):
            msg = "Allowed Address Pairs extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairSharedNetworkTest, cls).resource_setup()
        cls.network = cls.create_shared_network()
        cls.create_subnet(cls.network, client=cls.admin_client)

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-ffffffff1fff')
    def test_create_with_address_pair_blocked_on_other_network(self):
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.create_port(self.network,
                             allowed_address_pairs=self.allowed_address_pairs)

    @test.attr(type='smoke')
    @test.idempotent_id('86c3529b-1231-40de-803c-ffffffff2fff')
    def test_update_with_address_pair_blocked_on_other_network(self):
        port = self.create_port(self.network)
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.update_port(
                port, allowed_address_pairs=self.allowed_address_pairs)
