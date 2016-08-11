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

from tempest import test

from neutron.tests.tempest.api import base


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
        project_id = self.client.tenant_id
        self.assertEqual(project_id, network['tenant_id'])
        if test.is_extension_enabled('project-id', 'network'):
            self.assertEqual(project_id, network['project_id'])

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
        self.assertNotIn('tenant_id', network)
        self.assertNotIn('project_id', network)

    @test.idempotent_id('26f2b7a5-2cd1-4f3a-b11f-ad259b099b11')
    @test.requires_ext(extension="project-id", service="network")
    def test_show_network_fields_keystone_v3(self):

        def _check_show_network_fields(fields, expect_project_id,
                                       expect_tenant_id):
            params = {}
            if fields:
                params['fields'] = fields
            body = self.client.show_network(self.network['id'], **params)
            network = body['network']
            self.assertEqual(expect_project_id, 'project_id' in network)
            self.assertEqual(expect_tenant_id, 'tenant_id' in network)

        _check_show_network_fields(None, True, True)
        _check_show_network_fields(['tenant_id'], False, True)
        _check_show_network_fields(['project_id'], True, False)
        _check_show_network_fields(['project_id', 'tenant_id'], True, True)

    @test.idempotent_id('c72c1c0c-2193-4aca-ccc4-b1442640bbbb')
    @test.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_create_update_network_description(self):
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

    @test.idempotent_id('0cc0552f-afaf-4231-b7a7-c2a1774616da')
    @test.requires_ext(extension="project-id", service="network")
    def test_create_network_keystone_v3(self):
        project_id = self.client.tenant_id

        name = 'created-with-project_id'
        new_net = self.create_network_keystone_v3(name, project_id)
        self.assertEqual(name, new_net['name'])
        self.assertEqual(project_id, new_net['project_id'])
        self.assertEqual(project_id, new_net['tenant_id'])

        body = self.client.list_networks(id=new_net['id'])['networks'][0]
        self.assertEqual(name, body['name'])

        new_name = 'create-with-project_id-2'
        body = self.client.update_network(new_net['id'], name=new_name)
        new_net = body['network']
        self.assertEqual(new_name, new_net['name'])
        self.assertEqual(project_id, new_net['project_id'])
        self.assertEqual(project_id, new_net['tenant_id'])

    @test.idempotent_id('94e2a44c-3367-4253-8c2a-22deaf59e96c')
    @test.requires_ext(extension="dns-integration",
                       service="network")
    def test_create_update_network_dns_domain(self):
        domain1 = 'test.org.'
        body = self.create_network(dns_domain=domain1)
        self.assertEqual(domain1, body['dns_domain'])
        net_id = body['id']
        body = self.client.list_networks(id=net_id)['networks'][0]
        self.assertEqual(domain1, body['dns_domain'])
        domain2 = 'd.org.'
        body = self.client.update_network(net_id, dns_domain=domain2)
        self.assertEqual(domain2, body['network']['dns_domain'])
        body = self.client.show_network(net_id)['network']
        self.assertEqual(domain2, body['dns_domain'])

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

    @test.idempotent_id('a23186b9-aa6f-4b08-b877-35ca3b9cd54c')
    @test.requires_ext(extension="project-id", service="network")
    def test_list_networks_fields_keystone_v3(self):
        def _check_list_networks_fields(fields, expect_project_id,
                                        expect_tenant_id):
            params = {}
            if fields:
                params['fields'] = fields
            body = self.client.list_networks(**params)
            networks = body['networks']
            self.assertNotEmpty(networks, "Network list returned is empty")
            for network in networks:
                self.assertEqual(expect_project_id, 'project_id' in network)
                self.assertEqual(expect_tenant_id, 'tenant_id' in network)

        _check_list_networks_fields(None, True, True)
        _check_list_networks_fields(['tenant_id'], False, True)
        _check_list_networks_fields(['project_id'], True, False)
        _check_list_networks_fields(['project_id', 'tenant_id'], True, True)


class NetworksSearchCriteriaTest(base.BaseSearchCriteriaTest):

    resource = 'network'

    list_kwargs = {'shared': False, 'router:external': False}

    @classmethod
    def resource_setup(cls):
        super(NetworksSearchCriteriaTest, cls).resource_setup()
        for name in cls.resource_names:
            cls.create_network(network_name=name)

    @test.idempotent_id('de27d34a-bd9d-4516-83d6-81ef723f7d0d')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @test.idempotent_id('e767a160-59f9-4c4b-8dc1-72124a68640a')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @test.idempotent_id('71389852-f57b-49f2-b109-77b705e9e8af')
    def test_list_pagination(self):
        self._test_list_pagination()

    @test.idempotent_id('b7e153d2-37c3-48d4-8390-ec13498fee3d')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @test.idempotent_id('8a9c89df-0ee7-4c0d-8f1d-ec8f27cf362f')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @test.idempotent_id('79a52810-2156-4ab6-b577-9e46e58d4b58')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @test.idempotent_id('36a4671f-a542-442f-bc44-a8873ee778d1')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @test.idempotent_id('13eb066c-aa90-406d-b4c3-39595bf8f910')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()

    @test.idempotent_id('f1867fc5-e1d6-431f-bc9f-8b882e43a7f9')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()

    @test.idempotent_id('3574ec9b-a8b8-43e3-9c11-98f5875df6a9')
    def test_list_validation_filters(self):
        self._test_list_validation_filters()
