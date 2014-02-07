# Copyright (c) 2013 OpenStack Foundation
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

import collections
import testtools

from neutron.db import api as db
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions
from neutron.plugins.ml2.drivers.cisco.nexus import network_db_v2
from neutron.tests import base


class CiscoNetworkCredentialDbTest(base.BaseTestCase):

    """Unit tests for Cisco ML2 mechanism driver credentials database."""

    CredObj = collections.namedtuple('CredObj',
                                     'tenant_id cred_name user_name pwd')

    def setUp(self):
        super(CiscoNetworkCredentialDbTest, self).setUp()
        db.configure_db()
        self.addCleanup(db.clear_db)

    def _cred_test_obj(self, tenant_num, cred_num):
        """Create a Credential test object from a pair of numbers."""
        tenant_id = 'tenant_%s' % tenant_num
        cred_name = 'credential_%s_%s' % (tenant_num, cred_num)
        user_name = 'user_%s_%s' % (tenant_num, cred_num)
        pwd = 'password_%s_%s' % (tenant_num, cred_num)
        return self.CredObj(tenant_id, cred_name, user_name, pwd)

    def _assert_cred_equal(self, db_cred, test_cred):
        """Assert that a database credential matches a credential test obj."""
        self.assertEqual(db_cred.tenant_id, test_cred.tenant_id)
        self.assertEqual(db_cred.credential_name, test_cred.cred_name)
        self.assertEqual(db_cred.user_name, test_cred.user_name)
        self.assertEqual(db_cred.password, test_cred.pwd)

    def _get_credential(self, db_cred):
        """Lists credentials that match a credential's tenant and cred IDs."""
        return network_db_v2.get_credential(db_cred.tenant_id,
                                            db_cred.credential_id)

    def _get_credential_name(self, db_cred):
        """Lists credentials that match a cred's tenant ID and cred name."""
        return network_db_v2.get_credential_name(db_cred.tenant_id,
                                                 db_cred.credential_name)

    def _add_credential(self, test_cred):
        """Adds a credential to the database."""
        return network_db_v2.add_credential(test_cred.tenant_id,
                                            test_cred.cred_name,
                                            test_cred.user_name,
                                            test_cred.pwd)

    def _remove_credential(self, db_cred):
        """Removes a credential from the database."""
        return network_db_v2.remove_credential(db_cred.tenant_id,
                                               db_cred.credential_id)

    def _update_credential(self, db_cred, new_user_name=None,
                           new_password=None):
        """Updates a credential with a new user name and password."""
        return network_db_v2.update_credential(db_cred.tenant_id,
                                               db_cred.credential_id,
                                               new_user_name,
                                               new_password)

    def test_credential_add_remove(self):
        """Tests add and removal of credential to/from the database."""
        cred11 = self._cred_test_obj(1, 1)
        cred = self._add_credential(cred11)
        self._assert_cred_equal(cred, cred11)
        cred = self._remove_credential(cred)
        self._assert_cred_equal(cred, cred11)
        cred = self._remove_credential(cred)
        self.assertIsNone(cred)

    def test_credential_add_dup(self):
        """Tests addition of a duplicate credential to the database."""
        cred22 = self._cred_test_obj(2, 2)
        cred = self._add_credential(cred22)
        self._assert_cred_equal(cred, cred22)
        with testtools.ExpectedException(exceptions.CredentialAlreadyExists):
            self._add_credential(cred22)
        cred = self._remove_credential(cred)
        self._assert_cred_equal(cred, cred22)
        cred = self._remove_credential(cred)
        self.assertIsNone(cred)

    def test_credential_get(self):
        """Tests get of credentials by tenant ID and credential ID."""
        cred11 = self._cred_test_obj(1, 1)
        cred11_db = self._add_credential(cred11)
        cred21 = self._cred_test_obj(2, 1)
        cred21_db = self._add_credential(cred21)
        cred22 = self._cred_test_obj(2, 2)
        cred22_db = self._add_credential(cred22)

        cred = self._get_credential(cred11_db)
        self._assert_cred_equal(cred, cred11)
        cred = self._get_credential(cred21_db)
        self._assert_cred_equal(cred, cred21)
        cred = self._get_credential(cred22_db)
        self._assert_cred_equal(cred, cred22)

        with testtools.ExpectedException(exceptions.CredentialNotFound):
            network_db_v2.get_credential("dummyTenantId", "dummyCredentialId")

        cred_all_t1 = network_db_v2.get_all_credentials(cred11.tenant_id)
        self.assertEqual(len(cred_all_t1), 1)
        cred_all_t2 = network_db_v2.get_all_credentials(cred21.tenant_id)
        self.assertEqual(len(cred_all_t2), 2)

    def test_credential_get_name(self):
        """Tests get of credential by tenant ID and credential name."""
        cred11 = self._cred_test_obj(1, 1)
        cred11_db = self._add_credential(cred11)
        cred21 = self._cred_test_obj(2, 1)
        cred21_db = self._add_credential(cred21)
        cred22 = self._cred_test_obj(2, 2)
        cred22_db = self._add_credential(cred22)
        self.assertNotEqual(cred11_db.credential_id, cred21_db.credential_id)
        self.assertNotEqual(cred11_db.credential_id, cred22_db.credential_id)
        self.assertNotEqual(cred21_db.credential_id, cred22_db.credential_id)

        cred = self._get_credential_name(cred11_db)
        self._assert_cred_equal(cred, cred11)
        cred = self._get_credential_name(cred21_db)
        self._assert_cred_equal(cred, cred21)
        cred = self._get_credential_name(cred22_db)
        self._assert_cred_equal(cred, cred22)

        with testtools.ExpectedException(exceptions.CredentialNameNotFound):
            network_db_v2.get_credential_name("dummyTenantId",
                                              "dummyCredentialName")

    def test_credential_update(self):
        """Tests update of a credential with a new user name and password."""
        cred11 = self._cred_test_obj(1, 1)
        cred11_db = self._add_credential(cred11)
        self._update_credential(cred11_db)
        new_user_name = "new user name"
        new_pwd = "new password"
        new_credential = self._update_credential(
            cred11_db, new_user_name, new_pwd)
        expected_cred = self.CredObj(
            cred11.tenant_id, cred11.cred_name, new_user_name, new_pwd)
        self._assert_cred_equal(new_credential, expected_cred)
        new_credential = self._get_credential(cred11_db)
        self._assert_cred_equal(new_credential, expected_cred)
        with testtools.ExpectedException(exceptions.CredentialNotFound):
            network_db_v2.update_credential(
                "dummyTenantId", "dummyCredentialId", new_user_name, new_pwd)
