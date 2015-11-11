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
import uuid

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

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('9589e332-638e-476e-81bd-013d964aa3cb')
    @test.requires_ext(extension='address-scope', service='network')
    def test_create_subnetpool_associate_invalid_address_scope(self):
        subnetpool_data = copy.deepcopy(self._subnetpool_data)
        subnetpool_data['subnetpool']['address_scope_id'] = 'foo-addr-scope'
        self.assertRaises(lib_exc.BadRequest, self.client.create_subnetpool,
                          subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('3b6c5942-485d-4964-a560-55608af020b5')
    @test.requires_ext(extension='address-scope', service='network')
    def test_create_subnetpool_associate_non_exist_address_scope(self):
        subnetpool_data = copy.deepcopy(self._subnetpool_data)
        non_exist_address_scope_id = str(uuid.uuid4())
        subnetpool_data['subnetpool']['address_scope_id'] = (
            non_exist_address_scope_id)
        self.assertRaises(lib_exc.NotFound, self.client.create_subnetpool,
                          subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('2dfb4269-8657-485a-a053-b022e911456e')
    @test.requires_ext(extension='address-scope', service='network')
    def test_create_subnetpool_associate_address_scope_prefix_intersect(self):
        address_scope = self.create_address_scope(
            name=data_utils.rand_name('smoke-address-scope'))
        addr_scope_id = address_scope['id']
        pool_id = self._create_subnetpool(
            self.client, pool_values={'address_scope_id': addr_scope_id})
        self.addCleanup(self.client.delete_subnetpool, pool_id)
        subnetpool_data = {'subnetpool': {'name': 'foo-subnetpool',
                                          'prefixes': [u'10.11.12.13/24'],
                                          'min_prefixlen': '29',
                                          'address_scope_id': addr_scope_id}}
        self.assertRaises(lib_exc.Conflict, self.client.create_subnetpool,
                          subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('83a19a13-5384-42e2-b579-43fc69c80914')
    @test.requires_ext(extension='address-scope', service='network')
    def test_create_sp_associate_address_scope_multiple_prefix_intersect(self):
        address_scope = self.create_address_scope(
            name=data_utils.rand_name('smoke-address-scope'))
        addr_scope_id = address_scope['id']
        pool_values = {'address_scope_id': addr_scope_id,
                       'prefixes': [u'20.0.0.0/18', u'30.0.0.0/18']}

        pool_id = self._create_subnetpool(
            self.client, pool_values=pool_values)
        self.addCleanup(self.client.delete_subnetpool, pool_id)
        prefixes = [u'40.0.0.0/18', u'50.0.0.0/18', u'30.0.0.0/12']
        subnetpool_data = {'subnetpool': {'name': 'foo-subnetpool',
                                          'prefixes': prefixes,
                                          'min_prefixlen': '29',
                                          'address_scope_id': addr_scope_id}}
        self.assertRaises(lib_exc.Conflict, self.client.create_subnetpool,
                          subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('f06d8e7b-908b-4e94-b570-8156be6a4bf1')
    @test.requires_ext(extension='address-scope', service='network')
    def test_create_subnetpool_associate_address_scope_of_other_owner(self):
        address_scope = self.create_address_scope(
            name=data_utils.rand_name('smoke-address-scope'), is_admin=True)
        address_scope_id = address_scope['id']
        subnetpool_data = copy.deepcopy(self._subnetpool_data)
        subnetpool_data['subnetpool']['address_scope_id'] = address_scope_id
        self.assertRaises(lib_exc.NotFound, self.client.create_subnetpool,
                          subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('3396ec6c-cb80-4ebe-b897-84e904580bdf')
    @test.requires_ext(extension='address-scope', service='network')
    def test_tenant_create_subnetpool_associate_shared_address_scope(self):
        address_scope = self.create_address_scope(
            name=data_utils.rand_name('smoke-address-scope'), is_admin=True,
            shared=True)
        subnetpool_data = copy.deepcopy(self._subnetpool_data)
        subnetpool_data['subnetpool']['address_scope_id'] = (
            address_scope['id'])
        self.assertRaises(lib_exc.BadRequest, self.client.create_subnetpool,
                          subnetpool_data)

    @test.attr(type='smoke')
    @test.idempotent_id('6d3d9ad5-32d4-4d63-aa00-8c62f73e2881')
    @test.requires_ext(extension='address-scope', service='network')
    def test_update_subnetpool_associate_address_scope_of_other_owner(self):
        address_scope = self.create_address_scope(
            name=data_utils.rand_name('smoke-address-scope'), is_admin=True)
        address_scope_id = address_scope['id']
        pool_id = self._create_subnetpool(self.client)
        self.addCleanup(self.client.delete_subnetpool, pool_id)
        subnetpool_data = {'subnetpool': {'address_scope_id':
                                          address_scope_id}}
        self.assertRaises(lib_exc.NotFound, self.client.update_subnetpool,
                          pool_id, subnetpool_data)

    def _test_update_subnetpool_prefix_intersect_helper(
            self, pool_1_prefixes, pool_2_prefixes, pool_1_updated_prefixes):
        # create two subnet pools associating  to an address scope.
        # Updating the first subnet pool with the prefix intersecting
        # with the second one should be a failure
        address_scope = self.create_address_scope(
            name=data_utils.rand_name('smoke-address-scope'))
        addr_scope_id = address_scope['id']
        pool_values = {'address_scope_id': addr_scope_id,
                       'prefixes': pool_1_prefixes}
        pool_id_1 = self._create_subnetpool(self.client,
                                            pool_values=pool_values)
        self.addCleanup(self.client.delete_subnetpool, pool_id_1)
        pool_values = {'address_scope_id': addr_scope_id,
                       'prefixes': pool_2_prefixes}
        pool_id_2 = self._create_subnetpool(self.client,
                                            pool_values=pool_values)

        self.addCleanup(self.client.delete_subnetpool, pool_id_2)

        # now update the pool_id_1 with the prefix intersecting with
        # pool_id_2
        subnetpool_data = {'subnetpool': {'prefixes':
                                          pool_1_updated_prefixes}}
        self.assertRaises(lib_exc.Conflict, self.client.update_subnetpool,
                          pool_id_1, subnetpool_data)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('96006292-7214-40e0-a471-153fb76e6b31')
    @test.requires_ext(extension='address-scope', service='network')
    def test_update_subnetpool_prefix_intersect(self):
        pool_1_prefix = [u'20.0.0.0/18']
        pool_2_prefix = [u'20.10.0.0/24']
        pool_1_updated_prefix = [u'20.0.0.0/12']
        self._test_update_subnetpool_prefix_intersect_helper(
            pool_1_prefix, pool_2_prefix, pool_1_updated_prefix)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('4d3f8a79-c530-4e59-9acf-6c05968adbfe')
    @test.requires_ext(extension='address-scope', service='network')
    def test_update_subnetpool_multiple_prefix_intersect(self):
        pool_1_prefixes = [u'20.0.0.0/18', u'30.0.0.0/18']
        pool_2_prefixes = [u'20.10.0.0/24', u'40.0.0.0/18', '50.0.0.0/18']
        pool_1_updated_prefixes = [u'20.0.0.0/18', u'30.0.0.0/18',
                                   u'50.0.0.0/12']
        self._test_update_subnetpool_prefix_intersect_helper(
            pool_1_prefixes, pool_2_prefixes, pool_1_updated_prefixes)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('7438e49e-1351-45d8-937b-892059fb97f5')
    @test.requires_ext(extension='address-scope', service='network')
    def test_tenant_update_sp_prefix_associated_with_shared_addr_scope(self):
        address_scope = self.create_address_scope(
            name=data_utils.rand_name('smoke-address-scope'), is_admin=True,
            shared=True)
        addr_scope_id = address_scope['id']
        pool_values = {'prefixes': [u'20.0.0.0/18', u'30.0.0.0/18']}

        pool_id = self._create_subnetpool(
            self.client, pool_values=pool_values)
        self.addCleanup(self.client.delete_subnetpool, pool_id)

        # associate the subnetpool to the address scope as an admin
        subnetpool_data = {'subnetpool': {'address_scope_id':
                                          addr_scope_id}}
        self.admin_client.update_subnetpool(pool_id, subnetpool_data)
        body = self.admin_client.get_subnetpool(pool_id)
        self.assertEqual(addr_scope_id,
                         body['subnetpool']['address_scope_id'])

        # updating the subnetpool prefix by the tenant user should fail
        # since the tenant is not the owner of address scope
        update_prefixes = [u'20.0.0.0/18', u'30.0.0.0/18', u'40.0.0.0/18']
        subnetpool_data = {'subnetpool': {'prefixes': update_prefixes}}
        self.assertRaises(lib_exc.BadRequest, self.client.update_subnetpool,
                          pool_id, subnetpool_data)

        # admin can update the prefixes
        self.admin_client.update_subnetpool(pool_id, subnetpool_data)
        body = self.admin_client.get_subnetpool(pool_id)
        self.assertEqual(update_prefixes,
                         body['subnetpool']['prefixes'])
