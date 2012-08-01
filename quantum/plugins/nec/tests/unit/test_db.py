# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
import unittest

from quantum.common import utils
from quantum.plugins.nec.common import exceptions as nexc
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec.db import models as nmodels


class NECPluginV2DBTest(unittest.TestCase):
    """Class conisting of NECPluginV2 DB unit tests"""

    def setUp(self):
        """Setup for tests"""
        ndb.initialize()

    def tearDown(self):
        """Tear Down"""
        ndb.clear_db()

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test"""
        ofc_id = utils.str_uuid()
        quantum_id = utils.str_uuid()
        none = utils.str_uuid()
        return ofc_id, quantum_id, none

    def testa_add_ofc_item(self):
        """test add OFC item"""
        o, q, n = self.get_ofc_item_random_params()
        tenant = ndb.add_ofc_item(nmodels.OFCTenant, o, q)
        self.assertEqual(tenant.id, o)
        self.assertEqual(tenant.quantum_id, q)

        exception_raised = False
        try:
            ndb.add_ofc_item(nmodels.OFCTenant, o, q)
        except nexc.NECDBException:
            exception_raised = True
        self.assertTrue(exception_raised)

    def testb_get_ofc_item(self):
        """test get OFC item"""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(nmodels.OFCTenant, o, q)
        tenant = ndb.get_ofc_item(nmodels.OFCTenant, o)
        self.assertEqual(tenant.id, o)
        self.assertEqual(tenant.quantum_id, q)

        tenant_none = ndb.get_ofc_item(nmodels.OFCTenant, n)
        self.assertEqual(None, tenant_none)

    def testc_find_ofc_item(self):
        """test find OFC item"""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(nmodels.OFCTenant, o, q)
        tenant = ndb.find_ofc_item(nmodels.OFCTenant, q)
        self.assertEqual(tenant.id, o)
        self.assertEqual(tenant.quantum_id, q)

        tenant_none = ndb.find_ofc_item(nmodels.OFCTenant, n)
        self.assertEqual(None, tenant_none)

    def testc_del_ofc_item(self):
        """test delete OFC item"""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(nmodels.OFCTenant, o, q)
        ndb.del_ofc_item(nmodels.OFCTenant, o)

        tenant_none = ndb.get_ofc_item(nmodels.OFCTenant, q)
        self.assertEqual(None, tenant_none)
        tenant_none = ndb.find_ofc_item(nmodels.OFCTenant, q)
        self.assertEqual(None, tenant_none)

    def get_portinfo_random_params(self):
        """create random parameters for portinfo test"""
        port_id = utils.str_uuid()
        datapath_id = hex(random.randint(0, 0xffffffff))
        port_no = random.randint(1, 100)
        vlan_id = random.randint(0, 4095)
        mac = ':'.join(["%02x" % random.randint(0, 0xff) for x in range(6)])
        none = utils.str_uuid()
        return port_id, datapath_id, port_no, vlan_id, mac, none

    def testd_add_portinfo(self):
        """test add portinfo"""
        i, d, p, v, m, n = self.get_portinfo_random_params()
        portinfo = ndb.add_portinfo(i, d, p, v, m)
        self.assertEqual(portinfo.id, i)
        self.assertEqual(portinfo.datapath_id, d)
        self.assertEqual(portinfo.port_no, p)
        self.assertEqual(portinfo.vlan_id, v)
        self.assertEqual(portinfo.mac, m)

        exception_raised = False
        try:
            ndb.add_portinfo(i, d, p, v, m)
        except nexc.NECDBException:
            exception_raised = True
        self.assertTrue(exception_raised)

    def teste_get_portinfo(self):
        """test get portinfo"""
        i, d, p, v, m, n = self.get_portinfo_random_params()
        ndb.add_portinfo(i, d, p, v, m)
        portinfo = ndb.get_portinfo(i)
        self.assertEqual(portinfo.id, i)
        self.assertEqual(portinfo.datapath_id, d)
        self.assertEqual(portinfo.port_no, p)
        self.assertEqual(portinfo.vlan_id, v)
        self.assertEqual(portinfo.mac, m)

        portinfo_none = ndb.get_portinfo(n)
        self.assertEqual(None, portinfo_none)

    def testf_del_portinfo(self):
        """test delete portinfo"""
        i, d, p, v, m, n = self.get_portinfo_random_params()
        ndb.add_portinfo(i, d, p, v, m)
        portinfo = ndb.get_portinfo(i)
        self.assertEqual(portinfo.id, i)
        ndb.del_portinfo(i)
        portinfo_none = ndb.get_portinfo(i)
        self.assertEqual(None, portinfo_none)
