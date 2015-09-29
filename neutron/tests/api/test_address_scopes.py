# Copyright (c) 2015 Red Hat, Inc.
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
from tempest_lib import exceptions as lib_exc

from neutron.tests.api import base
from neutron.tests.api import clients
from neutron.tests.tempest import config
from neutron.tests.tempest import test

CONF = config.CONF
ADDRESS_SCOPE_NAME = 'smoke-address-scope'


class AddressScopeTestBase(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(AddressScopeTestBase, cls).resource_setup()
        try:
            creds = cls.isolated_creds.get_admin_creds()
            cls.os_adm = clients.Manager(credentials=creds)
        except NotImplementedError:
            msg = ("Missing Administrative Network API credentials "
                   "in configuration.")
            raise cls.skipException(msg)
        cls.admin_client = cls.os_adm.network_client

    def _create_address_scope(self, is_admin=False, **kwargs):
        name = data_utils.rand_name(ADDRESS_SCOPE_NAME)
        return self.create_address_scope(name=name, is_admin=is_admin,
                                         **kwargs)

    def _test_update_address_scope_helper(self, is_admin=False, shared=None):
        address_scope = self._create_address_scope(is_admin=is_admin)

        if is_admin:
            client = self.admin_client
        else:
            client = self.client

        kwargs = {'name': 'new_name'}
        if shared is not None:
            kwargs['shared'] = shared

        client.update_address_scope(address_scope['id'], **kwargs)
        body = client.show_address_scope(address_scope['id'])
        address_scope = body['address_scope']
        self.assertEqual('new_name', address_scope['name'])
        return address_scope


class AddressScopeTest(AddressScopeTestBase):

    @test.attr(type='smoke')
    @test.idempotent_id('045f9294-8b1a-4848-b6a8-edf1b41e9d06')
    def test_tenant_create_list_address_scope(self):
        address_scope = self._create_address_scope()
        body = self.client.list_address_scopes()
        returned_address_scopes = body['address_scopes']
        self.assertIn(address_scope['id'],
                      [a_s['id'] for a_s in returned_address_scopes],
                      "Created address scope id should be in the list")
        self.assertIn(address_scope['name'],
                      [a_s['name'] for a_s in returned_address_scopes],
                      "Created address scope name should be in the list")

    @test.attr(type='smoke')
    @test.idempotent_id('85e0326b-4c75-4b92-bd6e-7c7de6aaf05c')
    def test_show_address_scope(self):
        address_scope = self._create_address_scope()
        body = self.client.show_address_scope(
            address_scope['id'])
        returned_address_scope = body['address_scope']
        self.assertEqual(address_scope['id'], returned_address_scope['id'])
        self.assertEqual(address_scope['name'],
                         returned_address_scope['name'])
        self.assertFalse(returned_address_scope['shared'])

    @test.attr(type='smoke')
    @test.idempotent_id('85a259b2-ace6-4e32-9657-a9a392b452aa')
    def test_tenant_update_address_scope(self):
        self._test_update_address_scope_helper()

    @test.attr(type='smoke')
    @test.idempotent_id('22b3b600-72a8-4b60-bc94-0f29dd6271df')
    def test_delete_address_scope(self):
        address_scope = self._create_address_scope()
        self.client.delete_address_scope(address_scope['id'])
        self.assertRaises(lib_exc.NotFound, self.client.show_address_scope,
                          address_scope['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('5a06c287-8036-4d04-9d78-def8e06d43df')
    def test_admin_create_shared_address_scope(self):
        address_scope = self._create_address_scope(is_admin=True, shared=True)
        body = self.admin_client.show_address_scope(
            address_scope['id'])
        returned_address_scope = body['address_scope']
        self.assertEqual(address_scope['name'],
                         returned_address_scope['name'])
        self.assertTrue(returned_address_scope['shared'])

    @test.attr(type='smoke')
    @test.idempotent_id('e9e1ccdd-9ccd-4076-9503-71820529508b')
    def test_admin_update_shared_address_scope(self):
        address_scope = self._test_update_address_scope_helper(is_admin=True,
                                                               shared=True)
        self.assertTrue(address_scope['shared'])
