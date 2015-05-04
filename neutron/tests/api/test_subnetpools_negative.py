# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

import copy

from tempest_lib.common.utils import data_utils
from tempest_lib import exceptions as lib_exc

from neutron.tests.api import base
from neutron.tests.api import clients
from neutron.tests.tempest import config
from neutron.tests.tempest import test

CONF = config.CONF
SUBNETPOOL_NAME = 'smoke-subnetpool'


class SubnetPoolsNegativeTestJSON(base.BaseNetworkTest):

    smaller_prefix = u'10.11.12.0/26'

    @classmethod
    def resource_setup(cls):
        super(SubnetPoolsNegativeTestJSON, cls).resource_setup()
        min_prefixlen = '29'
        prefixes = [u'10.11.12.0/24']
        name = data_utils.rand_name(SUBNETPOOL_NAME)
        cls._subnetpool_data = {'subnetpool': {'name': name,
                                               'prefixes': prefixes,
                                               'min_prefixlen': min_prefixlen}}
        try:
            creds = cls.isolated_creds.get_admin_creds()
            cls.os_adm = clients.Manager(credentials=creds)
        except NotImplementedError:
            msg = ("Missing Administrative Network API credentials "
                   "in configuration.")
            raise cls.skipException(msg)
        cls.admin_client = cls.os_adm.network_client

    def _create_subnetpool(self, client, pool_values=None):
        subnetpool_data = copy.deepcopy(self._subnetpool_data)
        if pool_values:
            subnetpool_data['subnetpool'].update(pool_values)
        body = client.create_subnetpool(subnetpool_data)
        created_subnetpool = body['subnetpool']
        subnetpool_id = created_subnetpool['id']
        return subnetpool_id

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('0212a042-603a-4f46-99e0-e37de9374d30')
    def test_get_non_existent_subnetpool(self):
        non_exist_id = data_utils.rand_name('subnetpool')
        self.assertRaises(lib_exc.NotFound, self.client.get_subnetpool,
                          non_exist_id)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('dc9336e5-f28f-4658-a0b0-cc79e607007d')
    def test_tenant_get_not_shared_admin_subnetpool(self):
        pool_id = self._create_subnetpool(self.admin_client)
        self.addCleanup(self.admin_client.delete_subnetpool, pool_id)
        # None-shared admin subnetpool cannot be retrieved by tenant user.
        self.assertRaises(lib_exc.NotFound, self.client.get_subnetpool,
                          pool_id)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('5e1f2f86-d81a-498c-82ed-32a49f4dc4d3')
    def test_delete_non_existent_subnetpool(self):
        non_exist_id = data_utils.rand_name('subnetpool')
        self.assertRaises(lib_exc.NotFound, self.client.delete_subnetpool,
                          non_exist_id)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('d1143fe2-212b-4e23-a308-d18f7d8d78d6')
    def test_tenant_create_shared_subnetpool(self):
        # 'shared' subnetpool can only be created by admin.
        subnetpool_data = copy.deepcopy(self._subnetpool_data)
        subnetpool_data['subnetpool']['shared'] = 'True'
        self.assertRaises(lib_exc.Forbidden, self.client.create_subnetpool,
                          subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('4be84d30-60ca-4bd3-8512-db5b36ce1378')
    def test_update_non_existent_subnetpool(self):
        non_exist_id = data_utils.rand_name('subnetpool')
        self.assertRaises(lib_exc.NotFound, self.client.update_subnetpool,
                          non_exist_id, self._subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('e6cd6d87-6173-45dd-bf04-c18ea7ec7537')
    def test_update_subnetpool_not_modifiable_shared(self):
        # 'shared' attributes can be specified during creation.
        # But this attribute is not modifiable after creation.
        pool_id = self._create_subnetpool(self.admin_client)
        self.addCleanup(self.admin_client.delete_subnetpool, pool_id)
        subnetpool_data = {'subnetpool': {'shared': True}}
        self.assertRaises(lib_exc.BadRequest, self.client.update_subnetpool,
                          pool_id, subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('62f7c43b-bff1-4def-8bb7-4754b840aaad')
    def test_update_subnetpool_prefixes_shrink(self):
        # Shrink current subnetpool prefixes is not supported
        pool_id = self._create_subnetpool(self.client)
        subnetpool_data = {'subnetpool': {'prefixes': [self.smaller_prefix]}}
        self.addCleanup(self.client.delete_subnetpool, pool_id)
        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_subnetpool,
                          pool_id, subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('fc011824-153e-4469-97ad-9808eb88cae1')
    def test_create_subnet_different_pools_same_network(self):
        network = self.create_network(network_name='smoke-network')
        subnetpool_data = {'prefixes': ['192.168.0.0/16'],
                           'name': 'test-pool'}
        pool_id = self._create_subnetpool(self.admin_client, subnetpool_data)
        subnet = self.admin_client.create_subnet(
                    network_id=network['id'],
                    cidr='10.10.10.0/24',
                    ip_version=4,
                    gateway_ip=None)
        subnet_id = subnet['subnet']['id']
        self.addCleanup(self.admin_client.delete_subnet, subnet_id)
        self.addCleanup(self.admin_client.delete_subnetpool, pool_id)
        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.create_subnet,
                          network_id=network['id'],
                          ip_version=4,
                          subnetpool_id=pool_id)
