# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import random

from quantum.db import api as db_api
from quantum.openstack.common import uuidutils
from quantum.plugins.nec.common import exceptions as nexc
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec.db import models as nmodels  # noqa
from quantum.tests import base


class NECPluginV2DBTestBase(base.BaseTestCase):
    """Class conisting of NECPluginV2 DB unit tests"""

    def setUp(self):
        """Setup for tests"""
        super(NECPluginV2DBTestBase, self).setUp()
        ndb.initialize()
        self.session = db_api.get_session()
        self.addCleanup(ndb.clear_db)

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test"""
        ofc_id = uuidutils.generate_uuid()
        quantum_id = uuidutils.generate_uuid()
        none = uuidutils.generate_uuid()
        return ofc_id, quantum_id, none

    def get_portinfo_random_params(self):
        """create random parameters for portinfo test"""
        port_id = uuidutils.generate_uuid()
        datapath_id = hex(random.randint(0, 0xffffffff))
        port_no = random.randint(1, 100)
        vlan_id = random.randint(0, 4095)
        mac = ':'.join(["%02x" % random.randint(0, 0xff) for x in range(6)])
        none = uuidutils.generate_uuid()
        return port_id, datapath_id, port_no, vlan_id, mac, none


class NECPluginV2DBTest(NECPluginV2DBTestBase):

    def testa_add_ofc_item(self):
        """test add OFC item"""
        o, q, n = self.get_ofc_item_random_params()
        tenant = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.quantum_id, q)

        self.assertRaises(nexc.NECDBException,
                          ndb.add_ofc_item,
                          self.session, 'ofc_tenant', q, o)

    def testb_get_ofc_item(self):
        """test get OFC item"""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant = ndb.get_ofc_item(self.session, 'ofc_tenant', q)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.quantum_id, q)

        tenant_none = ndb.get_ofc_item(self.session, 'ofc_tenant', n)
        self.assertEqual(None, tenant_none)

    def testb_get_ofc_id(self):
        """test get OFC d"""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant_id = ndb.get_ofc_id(self.session, 'ofc_tenant', q)
        self.assertEqual(tenant_id, o)

        tenant_none = ndb.get_ofc_item(self.session, 'ofc_tenant', n)
        self.assertEqual(None, tenant_none)

    def testb_exists_ofc_item(self):
        """test get OFC d"""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        ret = ndb.exists_ofc_item(self.session, 'ofc_tenant', q)
        self.assertTrue(ret)

        tenant_none = ndb.get_ofc_item(self.session, 'ofc_tenant', n)
        self.assertEqual(None, tenant_none)

    def testc_find_ofc_item(self):
        """test find OFC item"""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant = ndb.find_ofc_item(self.session, 'ofc_tenant', o)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.quantum_id, q)

        tenant_none = ndb.find_ofc_item(self.session, 'ofc_tenant', n)
        self.assertEqual(None, tenant_none)

    def testc_del_ofc_item(self):
        """test delete OFC item"""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        ndb.del_ofc_item(self.session, 'ofc_tenant', q)

        tenant_none = ndb.get_ofc_item(self.session,
                                       'ofc_tenant', q)
        self.assertEqual(None, tenant_none)
        tenant_none = ndb.find_ofc_item(self.session,
                                        'ofc_tenant', o)
        self.assertEqual(None, tenant_none)

    def testd_add_portinfo(self):
        """test add portinfo"""
        i, d, p, v, m, n = self.get_portinfo_random_params()
        portinfo = ndb.add_portinfo(self.session, i, d, p, v, m)
        self.assertEqual(portinfo.id, i)
        self.assertEqual(portinfo.datapath_id, d)
        self.assertEqual(portinfo.port_no, p)
        self.assertEqual(portinfo.vlan_id, v)
        self.assertEqual(portinfo.mac, m)

        exception_raised = False
        try:
            ndb.add_portinfo(self.session, i, d, p, v, m)
        except nexc.NECDBException:
            exception_raised = True
        self.assertTrue(exception_raised)

    def teste_get_portinfo(self):
        """test get portinfo"""
        i, d, p, v, m, n = self.get_portinfo_random_params()
        ndb.add_portinfo(self.session, i, d, p, v, m)
        portinfo = ndb.get_portinfo(self.session, i)
        self.assertEqual(portinfo.id, i)
        self.assertEqual(portinfo.datapath_id, d)
        self.assertEqual(portinfo.port_no, p)
        self.assertEqual(portinfo.vlan_id, v)
        self.assertEqual(portinfo.mac, m)

        portinfo_none = ndb.get_portinfo(self.session, n)
        self.assertEqual(None, portinfo_none)

    def testf_del_portinfo(self):
        """test delete portinfo"""
        i, d, p, v, m, n = self.get_portinfo_random_params()
        ndb.add_portinfo(self.session, i, d, p, v, m)
        portinfo = ndb.get_portinfo(self.session, i)
        self.assertEqual(portinfo.id, i)
        ndb.del_portinfo(self.session, i)
        portinfo_none = ndb.get_portinfo(self.session, i)
        self.assertEqual(None, portinfo_none)


class NECPluginV2DBOldMappingTest(NECPluginV2DBTestBase):
    """Test related to old ID mapping"""

    # Mapping Table mode
    OLD = True
    NEW = False

    def test_add_ofc_item_new(self):
        o, q, n = self.get_ofc_item_random_params()
        ret = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, self.NEW)
        self.assertEqual(ret.ofc_id, o)
        self.assertEqual(ret.quantum_id, q)

        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.NEW)
        self.assertEqual(ret.ofc_id, o)
        self.assertEqual(ret.quantum_id, q)
        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.OLD)
        self.assertEqual(ret, None)

    def test_add_ofc_item_old(self):
        o, q, n = self.get_ofc_item_random_params()
        ret = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, self.OLD)
        self.assertEqual(ret.id, o)
        self.assertEqual(ret.quantum_id, q)

        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.NEW)
        self.assertEqual(ret, None)
        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.OLD)
        self.assertEqual(ret.id, o)
        self.assertEqual(ret.quantum_id, q)

    def _check_new_old_item(self, method, q_id, exp_new, exp_old):
        ret = method(self.session, 'ofc_tenant', q_id, self.NEW)
        self.assertEqual(ret, exp_new)
        ret = method(self.session, 'ofc_tenant', q_id, self.OLD)
        self.assertEqual(ret, exp_old)

    def test_get_ofc_id_new(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, self.NEW)
        self._check_new_old_item(ndb.get_ofc_id, q, o, None)
        ret = ndb.get_ofc_id_lookup_both(self.session, 'ofc_tenant', q)
        self.assertEqual(ret, o)

    def test_get_ofc_id_old(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, self.OLD)
        self._check_new_old_item(ndb.get_ofc_id, q, None, o)
        ret = ndb.get_ofc_id_lookup_both(self.session, 'ofc_tenant', q)
        self.assertEqual(ret, o)

    def _check_exists_ofc_item(self, mode, exp_new, exp_old):
        o, q, n = self.get_ofc_item_random_params()
        self._check_new_old_item(ndb.exists_ofc_item, q, False, False)
        self.assertFalse(ndb.exists_ofc_item_lookup_both(
            self.session, 'ofc_tenant', q))

        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, mode)
        self._check_new_old_item(ndb.exists_ofc_item, q, exp_new, exp_old)
        self.assertTrue(ndb.exists_ofc_item_lookup_both(
            self.session, 'ofc_tenant', q))

        ndb.del_ofc_item(self.session, 'ofc_tenant', q, mode)
        self._check_new_old_item(ndb.exists_ofc_item, q, False, False)
        self.assertFalse(ndb.exists_ofc_item_lookup_both(
            self.session, 'ofc_tenant', q))

    def test_exists_ofc_item_new(self):
        self._check_exists_ofc_item(self.NEW, True, False)

    def test_exists_ofc_item_old(self):
        self._check_exists_ofc_item(self.OLD, False, True)

    def _check_delete_ofc_item(self, mode, detect_mode=False):
        o, q, n = self.get_ofc_item_random_params()
        ret = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, mode)
        ofc_id = ret.ofc_id if mode == self.NEW else ret.id
        self.assertEqual(ofc_id, o)
        self.assertEqual(ret.quantum_id, q)
        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, mode)
        ofc_id = ret.ofc_id if mode == self.NEW else ret.id
        self.assertEqual(ofc_id, o)
        self.assertEqual(ret.quantum_id, q)

        if detect_mode:
            ndb.del_ofc_item_lookup_both(self.session, 'ofc_tenant', q)
        else:
            ndb.del_ofc_item(self.session, 'ofc_tenant', q, mode)

        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.NEW)
        self.assertEqual(ret, None)
        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.OLD)
        self.assertEqual(ret, None)

    def test_delete_ofc_item_new(self):
        self._check_delete_ofc_item(self.NEW)

    def test_delete_ofc_item_old(self):
        self._check_delete_ofc_item(self.OLD)

    def test_delete_ofc_item_with_auto_detect_new(self):
        self._check_delete_ofc_item(self.NEW, detect_mode=True)

    def test_delete_ofc_item_old_auto_detect_new(self):
        self._check_delete_ofc_item(self.OLD, detect_mode=True)
