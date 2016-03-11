# Copyright 2012 OpenStack Foundation
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

import itertools

from tempest import test

from neutron.tests.api import base
from neutron.tests.tempest import config

CONF = config.CONF


class NetworksTestJSON(base.BaseNetworkTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        list tenant's networks
        show a network
        show a tenant network details

    v2.0 of the Neutron API is assumed.
    """

    @classmethod
    def resource_setup(cls):
        super(NetworksTestJSON, cls).resource_setup()
        cls.network = cls.create_network()

    @test.attr(type='smoke')
    @test.idempotent_id('2bf13842-c93f-4a69-83ed-717d2ec3b44e')
    def test_show_network(self):
        # Verify the details of a network
        body = self.client.show_network(self.network['id'])
        network = body['network']
        fields = ['id', 'name']
        if test.is_extension_enabled('net-mtu', 'network'):
            fields.append('mtu')
        for key in fields:
            self.assertEqual(network[key], self.network[key])

    @test.attr(type='smoke')
    @test.idempotent_id('867819bb-c4b6-45f7-acf9-90edcf70aa5e')
    def test_show_network_fields(self):
        # Verify specific fields of a network
        fields = ['id', 'name']
        if test.is_extension_enabled('net-mtu', 'network'):
            fields.append('mtu')
        body = self.client.show_network(self.network['id'],
                                        fields=fields)
        network = body['network']
        self.assertEqual(sorted(network.keys()), sorted(fields))
        for field_name in fields:
            self.assertEqual(network[field_name], self.network[field_name])

    @test.attr(type='smoke')
    @test.idempotent_id('c72c1c0c-2193-4aca-ccc4-b1442640bbbb')
    def test_create_update_network_description(self):
        if not test.is_extension_enabled('standard-attr-description',
                                         'network'):
            msg = "standard-attr-description not enabled."
            raise self.skipException(msg)
        body = self.create_network(description='d1')
        self.assertEqual('d1', body['description'])
        net_id = body['id']
        body = self.client.list_networks(id=net_id)['networks'][0]
        self.assertEqual('d1', body['description'])
        body = self.client.update_network(body['id'],
                                          description='d2')
        self.assertEqual('d2', body['network']['description'])
        body = self.client.list_networks(id=net_id)['networks'][0]
        self.assertEqual('d2', body['description'])

    @test.attr(type='smoke')
    @test.idempotent_id('6ae6d24f-9194-4869-9c85-c313cb20e080')
    def test_list_networks_fields(self):
        # Verify specific fields of the networks
        fields = ['id', 'name']
        if test.is_extension_enabled('net-mtu', 'network'):
            fields.append('mtu')
        body = self.client.list_networks(fields=fields)
        networks = body['networks']
        self.assertNotEmpty(networks, "Network list returned is empty")
        for network in networks:
            self.assertEqual(sorted(network.keys()), sorted(fields))

    @test.attr(type='smoke')
    @test.idempotent_id('af774677-42a9-4e4b-bb58-16fe6a5bc1ec')
    def test_external_network_visibility(self):
        """Verifies user can see external networks but not subnets."""
        body = self.client.list_networks(**{'router:external': True})
        # shared external networks are excluded since their subnets are
        # visible
        networks = [network['id'] for network in body['networks']
                    if not network['shared']]
        self.assertNotEmpty(networks, "No external networks found")

        nonexternal = [net for net in body['networks'] if
                       not net['router:external']]
        self.assertEmpty(nonexternal, "Found non-external networks"
                                      " in filtered list (%s)." % nonexternal)
        self.assertIn(CONF.network.public_network_id, networks)

        subnets_iter = (network['subnets'] for network in body['networks'])
        # subnets_iter is a list (iterator) of lists. This flattens it to a
        # list of UUIDs
        public_subnets_iter = itertools.chain(*subnets_iter)
        body = self.client.list_subnets()
        subnets = [sub['id'] for sub in body['subnets']
                   if sub['id'] in public_subnets_iter]
        self.assertEmpty(subnets, "Public subnets visible")
