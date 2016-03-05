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

import copy

from tempest.lib.common.utils import data_utils
from tempest import test

from neutron.tests.api import base


class TestTimeStamp(base.BaseAdminNetworkTest):

    ## attributes for subnetpool
    min_prefixlen = '28'
    max_prefixlen = '31'
    _ip_version = 4
    subnet_cidr = '10.11.12.0/31'
    new_prefix = '10.11.15.0/24'
    larger_prefix = '10.11.0.0/16'

    @classmethod
    def skip_checks(cls):
        super(TestTimeStamp, cls).skip_checks()

        if not test.is_extension_enabled('timestamp_core', 'network'):
            raise cls.skipException("timestamp_core extension not enabled")

    @classmethod
    def resource_setup(cls):
        super(TestTimeStamp, cls).resource_setup()
        prefixes = ['10.11.12.0/24']
        cls._subnetpool_data = {'min_prefixlen': '29', 'prefixes': prefixes}

    def _create_subnetpool(self, is_admin=False, **kwargs):
        name = data_utils.rand_name('subnetpool-')
        subnetpool_data = copy.deepcopy(self._subnetpool_data)
        for key in subnetpool_data.keys():
            kwargs[key] = subnetpool_data[key]
        return self.create_subnetpool(name=name, is_admin=is_admin, **kwargs)

    @test.idempotent_id('462be770-b310-4df9-9c42-773217e4c8b1')
    def test_create_network_with_timestamp(self):
        network = self.create_network()
        # Verifies body contains timestamp fields
        self.assertIsNotNone(network['created_at'])
        self.assertIsNotNone(network['updated_at'])

    @test.idempotent_id('4db5417a-e11c-474d-a361-af00ebef57c5')
    def test_update_network_with_timestamp(self):
        network = self.create_network()
        origin_updated_at = network['updated_at']
        update_body = {'name': network['name'] + 'new'}
        body = self.admin_client.update_network(network['id'],
                                                **update_body)
        updated_network = body['network']
        new_updated_at = updated_network['updated_at']
        self.assertEqual(network['created_at'], updated_network['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @test.idempotent_id('2ac50ab2-7ebd-4e27-b3ce-a9e399faaea2')
    def test_show_networks_attribute_with_timestamp(self):
        network = self.create_network()
        body = self.client.show_network(network['id'])
        show_net = body['network']
        # verify the timestamp from creation and showed is same
        self.assertEqual(network['created_at'],
                         show_net['created_at'])
        self.assertEqual(network['updated_at'],
                         show_net['updated_at'])

    @test.idempotent_id('8ee55186-454f-4b97-9f9f-eb2772ee891c')
    def test_create_subnet_with_timestamp(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Verifies body contains timestamp fields
        self.assertIsNotNone(subnet['created_at'])
        self.assertIsNotNone(subnet['updated_at'])

    @test.idempotent_id('a490215a-6f4c-4af9-9a4c-57c41f1c4fa1')
    def test_update_subnet_with_timestamp(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        origin_updated_at = subnet['updated_at']
        update_body = {'name': subnet['name'] + 'new'}
        body = self.admin_client.update_subnet(subnet['id'],
                                               **update_body)
        updated_subnet = body['subnet']
        new_updated_at = updated_subnet['updated_at']
        self.assertEqual(subnet['created_at'], updated_subnet['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @test.idempotent_id('1836a086-e7cf-4141-bf57-0cfe79e8051e')
    def test_show_subnet_attribute_with_timestamp(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        body = self.client.show_subnet(subnet['id'])
        show_subnet = body['subnet']
        # verify the timestamp from creation and showed is same
        self.assertEqual(subnet['created_at'],
                         show_subnet['created_at'])
        self.assertEqual(subnet['updated_at'],
                         show_subnet['updated_at'])

    @test.idempotent_id('e2450a7b-d84f-4600-a093-45e78597bbac')
    def test_create_port_with_timestamp(self):
        network = self.create_network()
        port = self.create_port(network)
        # Verifies body contains timestamp fields
        self.assertIsNotNone(port['created_at'])
        self.assertIsNotNone(port['updated_at'])

    @test.idempotent_id('4241e0d3-54b4-46ce-a9a7-093fc764161b')
    def test_update_port_with_timestamp(self):
        network = self.create_network()
        port = self.create_port(network)
        origin_updated_at = port['updated_at']
        update_body = {'name': port['name'] + 'new'}
        body = self.admin_client.update_port(port['id'],
                                             **update_body)
        updated_port = body['port']
        new_updated_at = updated_port['updated_at']
        self.assertEqual(port['created_at'], updated_port['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @test.idempotent_id('584c6723-40b6-4f26-81dd-f508f9d9fb51')
    def test_show_port_attribute_with_timestamp(self):
        network = self.create_network()
        port = self.create_port(network)
        body = self.client.show_port(port['id'])
        show_port = body['port']
        # verify the timestamp from creation and showed is same
        self.assertEqual(port['created_at'],
                         show_port['created_at'])
        self.assertEqual(port['updated_at'],
                         show_port['updated_at'])

    @test.idempotent_id('87a8b196-4b90-44f0-b7f3-d2057d7d658e')
    def test_create_subnetpool_with_timestamp(self):
        sp = self._create_subnetpool()
        # Verifies body contains timestamp fields
        self.assertIsNotNone(sp['created_at'])
        self.assertIsNotNone(sp['updated_at'])

    @test.idempotent_id('d48c7578-c3d2-4f9b-a7a1-be2008c770a0')
    def test_update_subnetpool_with_timestamp(self):
        sp = self._create_subnetpool()
        origin_updated_at = sp['updated_at']
        update_body = {'name': sp['name'] + 'new',
                       'min_prefixlen': self.min_prefixlen,
                       'max_prefixlen': self.max_prefixlen}
        body = self.client.update_subnetpool(sp['id'], **update_body)
        updated_sp = body['subnetpool']
        new_updated_at = updated_sp['updated_at']
        self.assertEqual(sp['created_at'], updated_sp['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @test.idempotent_id('1d3970e6-bcf7-46cd-b7d7-0807759c73b4')
    def test_show_subnetpool_attribute_with_timestamp(self):
        sp = self._create_subnetpool()
        body = self.client.show_subnetpool(sp['id'])
        show_sp = body['subnetpool']
        # verify the timestamp from creation and showed is same
        self.assertEqual(sp['created_at'], show_sp['created_at'])
        self.assertEqual(sp['updated_at'], show_sp['updated_at'])
