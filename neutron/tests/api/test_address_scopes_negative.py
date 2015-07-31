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

from neutron.tests.api import test_address_scopes
from neutron.tests.tempest import test


class AddressScopeTestNegative(test_address_scopes.AddressScopeTestBase):

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('9c92ec34-0c50-4104-aa47-9ce98d5088df')
    def test_tenant_create_shared_address_scope(self):
        self.assertRaises(lib_exc.Forbidden, self._create_address_scope,
                          shared=True)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('a857b61e-bf53-4fab-b21a-b0daaf81b5bd')
    def test_tenant_update_address_scope_shared_true(self):
        self.assertRaises(lib_exc.Forbidden,
                          self._test_update_address_scope_helper, shared=True)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('a859ef2f-9c76-4e2e-ba0f-e0339a489e8c')
    def test_tenant_update_address_scope_shared_false(self):
        self.assertRaises(lib_exc.Forbidden,
                          self._test_update_address_scope_helper, shared=False)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('9b6dd7ad-cabb-4f55-bd5e-e61176ef41f6')
    def test_get_non_existent_address_scope(self):
        non_exist_id = data_utils.rand_name('address_scope')
        self.assertRaises(lib_exc.NotFound, self.client.show_address_scope,
                          non_exist_id)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('ef213552-f2da-487d-bf4a-e1705d115ff1')
    def test_tenant_get_not_shared_admin_address_scope(self):
        address_scope = self._create_address_scope(is_admin=True)
        # None-shared admin address scope cannot be retrieved by tenant user.
        self.assertRaises(lib_exc.NotFound, self.client.show_address_scope,
                          address_scope['id'])

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('5c25dc6a-1e92-467a-9cc7-cda74b6003db')
    def test_delete_non_existent_address_scope(self):
        non_exist_id = data_utils.rand_name('address_scope')
        self.assertRaises(lib_exc.NotFound, self.client.delete_address_scope,
                          non_exist_id)

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('47c25dc5-e886-4a84-88c3-ac5031969661')
    def test_update_non_existent_address_scope(self):
        non_exist_id = data_utils.rand_name('address_scope')
        self.assertRaises(lib_exc.NotFound, self.client.update_address_scope,
                          non_exist_id, name='foo-name')

    @test.attr(type=['negative', 'smoke'])
    @test.idempotent_id('702d0515-82cb-4207-b0d9-703336e54665')
    def test_update_shared_address_scope_to_unshare(self):
        address_scope = self._create_address_scope(is_admin=True, shared=True)
        self.assertRaises(lib_exc.BadRequest,
                          self.admin_client.update_address_scope,
                          address_scope['id'], name='new-name', shared=False)
