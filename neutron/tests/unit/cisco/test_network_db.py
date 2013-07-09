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
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.db import network_db_v2 as cdb
from neutron.tests import base


class CiscoNetworkQosDbTest(base.BaseTestCase):

    """Unit tests for cisco.db.network_models_v2.QoS model."""

    QosObj = collections.namedtuple('QosObj', 'tenant qname desc')

    def setUp(self):
        super(CiscoNetworkQosDbTest, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.addCleanup(db.clear_db)

    def _qos_test_obj(self, tnum, qnum, desc=None):
        """Create a Qos test object from a pair of numbers."""
        if desc is None:
            desc = 'test qos %s-%s' % (str(tnum), str(qnum))
        tenant = 'tenant_%s' % str(tnum)
        qname = 'qos_%s' % str(qnum)
        return self.QosObj(tenant, qname, desc)

    def _assert_equal(self, qos, qos_obj):
        self.assertEqual(qos.tenant_id, qos_obj.tenant)
        self.assertEqual(qos.qos_name, qos_obj.qname)
        self.assertEqual(qos.qos_desc, qos_obj.desc)

    def test_qos_add_remove(self):
        qos11 = self._qos_test_obj(1, 1)
        qos = cdb.add_qos(qos11.tenant, qos11.qname, qos11.desc)
        self._assert_equal(qos, qos11)
        qos_id = qos.qos_id
        qos = cdb.remove_qos(qos11.tenant, qos_id)
        self._assert_equal(qos, qos11)
        qos = cdb.remove_qos(qos11.tenant, qos_id)
        self.assertIsNone(qos)

    def test_qos_add_dup(self):
        qos22 = self._qos_test_obj(2, 2)
        qos = cdb.add_qos(qos22.tenant, qos22.qname, qos22.desc)
        self._assert_equal(qos, qos22)
        qos_id = qos.qos_id
        with testtools.ExpectedException(c_exc.QosNameAlreadyExists):
            cdb.add_qos(qos22.tenant, qos22.qname, "duplicate 22")
        qos = cdb.remove_qos(qos22.tenant, qos_id)
        self._assert_equal(qos, qos22)
        qos = cdb.remove_qos(qos22.tenant, qos_id)
        self.assertIsNone(qos)

    def test_qos_get(self):
        qos11 = self._qos_test_obj(1, 1)
        qos11_id = cdb.add_qos(qos11.tenant, qos11.qname, qos11.desc).qos_id
        qos21 = self._qos_test_obj(2, 1)
        qos21_id = cdb.add_qos(qos21.tenant, qos21.qname, qos21.desc).qos_id
        qos22 = self._qos_test_obj(2, 2)
        qos22_id = cdb.add_qos(qos22.tenant, qos22.qname, qos22.desc).qos_id

        qos = cdb.get_qos(qos11.tenant, qos11_id)
        self._assert_equal(qos, qos11)
        qos = cdb.get_qos(qos21.tenant, qos21_id)
        self._assert_equal(qos, qos21)
        qos = cdb.get_qos(qos21.tenant, qos22_id)
        self._assert_equal(qos, qos22)

        with testtools.ExpectedException(c_exc.QosNotFound):
            cdb.get_qos(qos11.tenant, "dummyQosId")
        with testtools.ExpectedException(c_exc.QosNotFound):
            cdb.get_qos(qos11.tenant, qos21_id)
        with testtools.ExpectedException(c_exc.QosNotFound):
            cdb.get_qos(qos21.tenant, qos11_id)

        qos_all_t1 = cdb.get_all_qoss(qos11.tenant)
        self.assertEqual(len(qos_all_t1), 1)
        qos_all_t2 = cdb.get_all_qoss(qos21.tenant)
        self.assertEqual(len(qos_all_t2), 2)
        qos_all_t3 = cdb.get_all_qoss("tenant3")
        self.assertEqual(len(qos_all_t3), 0)

    def test_qos_update(self):
        qos11 = self._qos_test_obj(1, 1)
        qos11_id = cdb.add_qos(qos11.tenant, qos11.qname, qos11.desc).qos_id
        cdb.update_qos(qos11.tenant, qos11_id)
        new_qname = "new qos name"
        new_qos = cdb.update_qos(qos11.tenant, qos11_id, new_qname)
        expected_qobj = self.QosObj(qos11.tenant, new_qname, qos11.desc)
        self._assert_equal(new_qos, expected_qobj)
        new_qos = cdb.get_qos(qos11.tenant, qos11_id)
        self._assert_equal(new_qos, expected_qobj)
        with testtools.ExpectedException(c_exc.QosNotFound):
            cdb.update_qos(qos11.tenant, "dummyQosId")


class CiscoNetworkCredentialDbTest(base.BaseTestCase):

    """Unit tests for cisco.db.network_models_v2.Credential model."""

    CredObj = collections.namedtuple('CredObj', 'cname usr pwd ctype')

    def setUp(self):
        super(CiscoNetworkCredentialDbTest, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.addCleanup(db.clear_db)

    def _cred_test_obj(self, tnum, cnum):
        """Create a Credential test object from a pair of numbers."""
        cname = 'credential_%s_%s' % (str(tnum), str(cnum))
        usr = 'User_%s_%s' % (str(tnum), str(cnum))
        pwd = 'Password_%s_%s' % (str(tnum), str(cnum))
        ctype = 'ctype_%s' % str(tnum)
        return self.CredObj(cname, usr, pwd, ctype)

    def _assert_equal(self, credential, cred_obj):
        self.assertEqual(credential.type, cred_obj.ctype)
        self.assertEqual(credential.credential_name, cred_obj.cname)
        self.assertEqual(credential.user_name, cred_obj.usr)
        self.assertEqual(credential.password, cred_obj.pwd)

    def test_credential_add_remove(self):
        cred11 = self._cred_test_obj(1, 1)
        cred = cdb.add_credential(
            cred11.cname, cred11.usr, cred11.pwd, cred11.ctype)
        self._assert_equal(cred, cred11)
        cred_id = cred.credential_id
        cred = cdb.remove_credential(cred_id)
        self._assert_equal(cred, cred11)
        cred = cdb.remove_credential(cred_id)
        self.assertIsNone(cred)

    def test_credential_add_dup(self):
        cred22 = self._cred_test_obj(2, 2)
        cred = cdb.add_credential(
            cred22.cname, cred22.usr, cred22.pwd, cred22.ctype)
        self._assert_equal(cred, cred22)
        cred_id = cred.credential_id
        with testtools.ExpectedException(c_exc.CredentialAlreadyExists):
            cdb.add_credential(
                cred22.cname, cred22.usr, cred22.pwd, cred22.ctype)
        cred = cdb.remove_credential(cred_id)
        self._assert_equal(cred, cred22)
        cred = cdb.remove_credential(cred_id)
        self.assertIsNone(cred)

    def test_credential_get_id(self):
        cred11 = self._cred_test_obj(1, 1)
        cred11_id = cdb.add_credential(
            cred11.cname, cred11.usr, cred11.pwd, cred11.ctype).credential_id
        cred21 = self._cred_test_obj(2, 1)
        cred21_id = cdb.add_credential(
            cred21.cname, cred21.usr, cred21.pwd, cred21.ctype).credential_id
        cred22 = self._cred_test_obj(2, 2)
        cred22_id = cdb.add_credential(
            cred22.cname, cred22.usr, cred22.pwd, cred22.ctype).credential_id

        cred = cdb.get_credential(cred11_id)
        self._assert_equal(cred, cred11)
        cred = cdb.get_credential(cred21_id)
        self._assert_equal(cred, cred21)
        cred = cdb.get_credential(cred22_id)
        self._assert_equal(cred, cred22)

        with testtools.ExpectedException(c_exc.CredentialNotFound):
            cdb.get_credential("dummyCredentialId")

        cred_all_t1 = cdb.get_all_credentials()
        self.assertEqual(len(cred_all_t1), 3)

    def test_credential_get_name(self):
        cred11 = self._cred_test_obj(1, 1)
        cred11_id = cdb.add_credential(
            cred11.cname, cred11.usr, cred11.pwd, cred11.ctype).credential_id
        cred21 = self._cred_test_obj(2, 1)
        cred21_id = cdb.add_credential(
            cred21.cname, cred21.usr, cred21.pwd, cred21.ctype).credential_id
        cred22 = self._cred_test_obj(2, 2)
        cred22_id = cdb.add_credential(
            cred22.cname, cred22.usr, cred22.pwd, cred22.ctype).credential_id
        self.assertNotEqual(cred11_id, cred21_id)
        self.assertNotEqual(cred11_id, cred22_id)
        self.assertNotEqual(cred21_id, cred22_id)

        cred = cdb.get_credential_name(cred11.cname)
        self._assert_equal(cred, cred11)
        cred = cdb.get_credential_name(cred21.cname)
        self._assert_equal(cred, cred21)
        cred = cdb.get_credential_name(cred22.cname)
        self._assert_equal(cred, cred22)

        with testtools.ExpectedException(c_exc.CredentialNameNotFound):
            cdb.get_credential_name("dummyCredentialName")

    def test_credential_update(self):
        cred11 = self._cred_test_obj(1, 1)
        cred11_id = cdb.add_credential(
            cred11.cname, cred11.usr, cred11.pwd, cred11.ctype).credential_id
        cdb.update_credential(cred11_id)
        new_usr = "new user name"
        new_pwd = "new password"
        new_credential = cdb.update_credential(
            cred11_id, new_usr, new_pwd)
        expected_cred = self.CredObj(
            cred11.cname, new_usr, new_pwd, cred11.ctype)
        self._assert_equal(new_credential, expected_cred)
        new_credential = cdb.get_credential(cred11_id)
        self._assert_equal(new_credential, expected_cred)
        with testtools.ExpectedException(c_exc.CredentialNotFound):
            cdb.update_credential(
                "dummyCredentialId", new_usr, new_pwd)
