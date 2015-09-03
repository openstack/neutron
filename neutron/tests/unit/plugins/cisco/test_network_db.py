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
import mock
import testtools

from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.common import cisco_credentials_v2
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.common import config as config
from neutron.plugins.cisco.db import network_db_v2 as cdb
from neutron.plugins.cisco import network_plugin
from neutron.tests.unit import testlib_api


class CiscoNetworkDbTest(testlib_api.SqlTestCase):

    """Base class for Cisco network database unit tests."""

    def setUp(self):
        super(CiscoNetworkDbTest, self).setUp()

        # The Cisco network plugin includes a thin layer of QoS and
        # credential API methods which indirectly call Cisco QoS and
        # credential database access methods. For better code coverage,
        # this test suite will make calls to the QoS and credential database
        # access methods indirectly through the network plugin. The network
        # plugin's init function can be mocked out for this purpose.
        def new_network_plugin_init(instance):
            pass
        with mock.patch.object(network_plugin.PluginV2,
                               '__init__', new=new_network_plugin_init):
            self._network_plugin = network_plugin.PluginV2()


class CiscoNetworkQosDbTest(CiscoNetworkDbTest):

    """Unit tests for Cisco network QoS database model."""

    QosObj = collections.namedtuple('QosObj', 'tenant qname desc')

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
        qos = self._network_plugin.create_qos(qos11.tenant, qos11.qname,
                                              qos11.desc)
        self._assert_equal(qos, qos11)
        qos_id = qos.qos_id
        qos = self._network_plugin.delete_qos(qos11.tenant, qos_id)
        self._assert_equal(qos, qos11)
        qos = self._network_plugin.delete_qos(qos11.tenant, qos_id)
        self.assertIsNone(qos)

    def test_qos_add_dup(self):
        qos22 = self._qos_test_obj(2, 2)
        qos = self._network_plugin.create_qos(qos22.tenant, qos22.qname,
                                              qos22.desc)
        self._assert_equal(qos, qos22)
        qos_id = qos.qos_id
        with testtools.ExpectedException(c_exc.QosNameAlreadyExists):
            self._network_plugin.create_qos(qos22.tenant, qos22.qname,
                                            "duplicate 22")
        qos = self._network_plugin.delete_qos(qos22.tenant, qos_id)
        self._assert_equal(qos, qos22)
        qos = self._network_plugin.delete_qos(qos22.tenant, qos_id)
        self.assertIsNone(qos)

    def test_qos_get(self):
        qos11 = self._qos_test_obj(1, 1)
        qos11_id = self._network_plugin.create_qos(qos11.tenant, qos11.qname,
                                                   qos11.desc).qos_id
        qos21 = self._qos_test_obj(2, 1)
        qos21_id = self._network_plugin.create_qos(qos21.tenant, qos21.qname,
                                                   qos21.desc).qos_id
        qos22 = self._qos_test_obj(2, 2)
        qos22_id = self._network_plugin.create_qos(qos22.tenant, qos22.qname,
                                                   qos22.desc).qos_id

        qos = self._network_plugin.get_qos_details(qos11.tenant, qos11_id)
        self._assert_equal(qos, qos11)
        qos = self._network_plugin.get_qos_details(qos21.tenant, qos21_id)
        self._assert_equal(qos, qos21)
        qos = self._network_plugin.get_qos_details(qos21.tenant, qos22_id)
        self._assert_equal(qos, qos22)

        with testtools.ExpectedException(c_exc.QosNotFound):
            self._network_plugin.get_qos_details(qos11.tenant, "dummyQosId")
        with testtools.ExpectedException(c_exc.QosNotFound):
            self._network_plugin.get_qos_details(qos11.tenant, qos21_id)
        with testtools.ExpectedException(c_exc.QosNotFound):
            self._network_plugin.get_qos_details(qos21.tenant, qos11_id)

        qos_all_t1 = self._network_plugin.get_all_qoss(qos11.tenant)
        self.assertEqual(len(qos_all_t1), 1)
        qos_all_t2 = self._network_plugin.get_all_qoss(qos21.tenant)
        self.assertEqual(len(qos_all_t2), 2)
        qos_all_t3 = self._network_plugin.get_all_qoss("tenant3")
        self.assertEqual(len(qos_all_t3), 0)

    def test_qos_update(self):
        qos11 = self._qos_test_obj(1, 1)
        qos11_id = self._network_plugin.create_qos(qos11.tenant, qos11.qname,
                                                   qos11.desc).qos_id
        self._network_plugin.rename_qos(qos11.tenant, qos11_id,
                                        new_name=None)
        new_qname = "new qos name"
        new_qos = self._network_plugin.rename_qos(qos11.tenant, qos11_id,
                                                  new_qname)
        expected_qobj = self.QosObj(qos11.tenant, new_qname, qos11.desc)
        self._assert_equal(new_qos, expected_qobj)
        new_qos = self._network_plugin.get_qos_details(qos11.tenant, qos11_id)
        self._assert_equal(new_qos, expected_qobj)
        with testtools.ExpectedException(c_exc.QosNotFound):
            self._network_plugin.rename_qos(qos11.tenant, "dummyQosId",
                                            new_name=None)


class CiscoNetworkCredentialDbTest(CiscoNetworkDbTest):

    """Unit tests for Cisco network credentials database model."""

    CredObj = collections.namedtuple('CredObj', 'cname usr pwd ctype')

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

        cred = self._network_plugin.get_credential_details(cred11_id)
        self._assert_equal(cred, cred11)
        cred = self._network_plugin.get_credential_details(cred21_id)
        self._assert_equal(cred, cred21)
        cred = self._network_plugin.get_credential_details(cred22_id)
        self._assert_equal(cred, cred22)

        with testtools.ExpectedException(c_exc.CredentialNotFound):
            self._network_plugin.get_credential_details("dummyCredentialId")

        cred_all_t1 = self._network_plugin.get_all_credentials()
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
        self._network_plugin.rename_credential(cred11_id, new_name=None,
                                               new_password=None)
        new_usr = "new user name"
        new_pwd = "new password"
        new_credential = self._network_plugin.rename_credential(
            cred11_id, new_usr, new_pwd)
        expected_cred = self.CredObj(
            cred11.cname, new_usr, new_pwd, cred11.ctype)
        self._assert_equal(new_credential, expected_cred)
        new_credential = self._network_plugin.get_credential_details(
            cred11_id)
        self._assert_equal(new_credential, expected_cred)
        with testtools.ExpectedException(c_exc.CredentialNotFound):
            self._network_plugin.rename_credential(
                "dummyCredentialId", new_usr, new_pwd)

    def test_get_credential_not_found_exception(self):
        self.assertRaises(c_exc.CredentialNotFound,
                          self._network_plugin.get_credential_details,
                          "dummyCredentialId")

    def test_credential_delete_all_n1kv(self):
        cred_nexus_1 = self._cred_test_obj('nexus', 1)
        cred_nexus_2 = self._cred_test_obj('nexus', 2)
        cred_n1kv_1 = self.CredObj('n1kv-1', 'cisco', '123456', 'n1kv')
        cred_n1kv_2 = self.CredObj('n1kv-2', 'cisco', '123456', 'n1kv')
        cred_nexus_1_id = cdb.add_credential(
            cred_nexus_1.cname, cred_nexus_1.usr,
            cred_nexus_1.pwd, cred_nexus_1.ctype).credential_id
        cred_nexus_2_id = cdb.add_credential(
            cred_nexus_2.cname, cred_nexus_2.usr,
            cred_nexus_2.pwd, cred_nexus_2.ctype).credential_id
        cred_n1kv_1_id = cdb.add_credential(
            cred_n1kv_1.cname, cred_n1kv_1.usr,
            cred_n1kv_1.pwd, cred_n1kv_1.ctype).credential_id
        cred_n1kv_2_id = cdb.add_credential(
            cred_n1kv_2.cname, cred_n1kv_2.usr,
            cred_n1kv_2.pwd, cred_n1kv_2.ctype).credential_id
        cdb.delete_all_n1kv_credentials()
        cred = cdb.get_credential(cred_nexus_1_id)
        self.assertIsNotNone(cred)
        cred = cdb.get_credential(cred_nexus_2_id)
        self.assertIsNotNone(cred)
        self.assertRaises(c_exc.CredentialNotFound,
                          cdb.get_credential, cred_n1kv_1_id)
        self.assertRaises(c_exc.CredentialNotFound,
                          cdb.get_credential, cred_n1kv_2_id)


class CiscoCredentialStoreTest(testlib_api.SqlTestCase):

    """Cisco Credential Store unit tests."""

    def test_cred_store_init_duplicate_creds_ignored(self):
        """Check that with multi store instances, dup creds are ignored."""
        # Create a device dictionary containing credentials for 1 switch.
        dev_dict = {
            ('dev_id', '1.1.1.1', cisco_constants.USERNAME): 'user_1',
            ('dev_id', '1.1.1.1', cisco_constants.PASSWORD): 'password_1',
            ('dev_id', '1.1.1.1', 'host_a'): '1/1',
            ('dev_id', '1.1.1.1', 'host_b'): '1/2',
            ('dev_id', '1.1.1.1', 'host_c'): '1/3',
        }
        with mock.patch.object(config, 'get_device_dictionary',
                               return_value=dev_dict):
            # Create and initialize 2 instances of credential store.
            cisco_credentials_v2.Store().initialize()
            cisco_credentials_v2.Store().initialize()
            # There should be only 1 switch credential in the database.
            self.assertEqual(len(cdb.get_all_credentials()), 1)
