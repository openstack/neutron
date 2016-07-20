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

from tempest import test

from neutron.tests.tempest.api import base


class PortsTestJSON(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(PortsTestJSON, cls).resource_setup()
        cls.network = cls.create_network()

    @test.idempotent_id('c72c1c0c-2193-4aca-bbb4-b1442640bbbb')
    @test.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_create_update_port_description(self):
        body = self.create_port(self.network,
                                description='d1')
        self.assertEqual('d1', body['description'])
        body = self.client.list_ports(id=body['id'])['ports'][0]
        self.assertEqual('d1', body['description'])
        body = self.client.update_port(body['id'],
                                       description='d2')
        self.assertEqual('d2', body['port']['description'])
        body = self.client.list_ports(id=body['port']['id'])['ports'][0]
        self.assertEqual('d2', body['description'])

    @test.idempotent_id('c72c1c0c-2193-4aca-bbb4-b1442640c123')
    def test_change_dhcp_flag_then_create_port(self):
        s = self.create_subnet(self.network, enable_dhcp=False)
        self.create_port(self.network)
        self.client.update_subnet(s['id'], enable_dhcp=True)
        self.create_port(self.network)


class PortsSearchCriteriaTest(base.BaseSearchCriteriaTest):

    resource = 'port'

    @classmethod
    def resource_setup(cls):
        super(PortsSearchCriteriaTest, cls).resource_setup()
        net = cls.create_network(network_name='port-search-test-net')
        for name in cls.resource_names:
            cls.create_port(net, name=name)

    @test.idempotent_id('9ab73df4-960a-4ae3-87d3-60992b8d3e2d')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @test.idempotent_id('b426671d-7270-430f-82ff-8f33eec93010')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @test.idempotent_id('a202fdc8-6616-45df-b6a0-463932de6f94')
    def test_list_pagination(self):
        self._test_list_pagination()

    @test.idempotent_id('f4723b8e-8186-4b9a-bf9e-57519967e048')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @test.idempotent_id('fcd02a7a-f07e-4d5e-b0ca-b58e48927a9b')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @test.idempotent_id('3afe7024-77ab-4cfe-824b-0b2bf4217727')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()

    @test.idempotent_id('b8857391-dc44-40cc-89b7-2800402e03ce')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @test.idempotent_id('4e51e9c9-ceae-4ec0-afd4-147569247699')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @test.idempotent_id('74293e59-d794-4a93-be09-38667199ef68')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()
