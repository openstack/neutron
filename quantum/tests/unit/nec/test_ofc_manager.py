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

import unittest

from quantum.common import utils
from quantum.plugins.nec.common import config
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec.db import models as nmodels
from quantum.plugins.nec import ofc_manager


class OFCManagerTest(unittest.TestCase):
    """Class conisting of OFCManager unit tests"""

    def setUp(self):
        driver = "quantum.tests.unit.nec.stub_ofc_driver.StubOFCDriver"
        config.CONF.set_override('driver', driver, 'OFC')
        ndb.initialize()
        self.ofc = ofc_manager.OFCManager()

    def tearDown(self):
        ndb.clear_db()

    def get_random_params(self):
        """create random parameters for portinfo test"""
        tenant = utils.str_uuid()
        network = utils.str_uuid()
        port = utils.str_uuid()
        _filter = utils.str_uuid()
        none = utils.str_uuid()
        return tenant, network, port, _filter, none

    def testa_create_ofc_tenant(self):
        """test create ofc_tenant"""
        t, n, p, f, none = self.get_random_params()
        self.assertFalse(ndb.find_ofc_item(nmodels.OFCTenant, t))
        self.ofc.create_ofc_tenant(t)
        self.assertTrue(ndb.find_ofc_item(nmodels.OFCTenant, t))
        tenant = ndb.find_ofc_item(nmodels.OFCTenant, t)
        self.assertEqual(tenant.id, "ofc-" + t[:-4])

    def testb_exists_ofc_tenant(self):
        """test exists_ofc_tenant"""
        t, n, p, f, none = self.get_random_params()
        self.assertFalse(self.ofc.exists_ofc_tenant(t))
        self.ofc.create_ofc_tenant(t)
        self.assertTrue(self.ofc.exists_ofc_tenant(t))

    def testc_delete_ofc_tenant(self):
        """test delete ofc_tenant"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.assertTrue(ndb.find_ofc_item(nmodels.OFCTenant, t))
        self.ofc.delete_ofc_tenant(t)
        self.assertFalse(ndb.find_ofc_item(nmodels.OFCTenant, t))

    def testd_create_ofc_network(self):
        """test create ofc_network"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.assertFalse(ndb.find_ofc_item(nmodels.OFCNetwork, n))
        self.ofc.create_ofc_network(t, n)
        self.assertTrue(ndb.find_ofc_item(nmodels.OFCNetwork, n))
        network = ndb.find_ofc_item(nmodels.OFCNetwork, n)
        self.assertEqual(network.id, "ofc-" + n[:-4])

    def teste_exists_ofc_network(self):
        """test exists_ofc_network"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.assertFalse(self.ofc.exists_ofc_network(n))
        self.ofc.create_ofc_network(t, n)
        self.assertTrue(self.ofc.exists_ofc_network(n))

    def testf_delete_ofc_network(self):
        """test delete ofc_network"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.ofc.create_ofc_network(t, n)
        self.assertTrue(ndb.find_ofc_item(nmodels.OFCNetwork, n))
        self.ofc.delete_ofc_network(t, n)
        self.assertFalse(ndb.find_ofc_item(nmodels.OFCNetwork, n))

    def testg_create_ofc_port(self):
        """test create ofc_port"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.ofc.create_ofc_network(t, n)
        ndb.add_portinfo(p, "0xabc", 1, 65535, "00:11:22:33:44:55")
        self.assertFalse(ndb.find_ofc_item(nmodels.OFCPort, p))
        self.ofc.create_ofc_port(t, n, p)
        self.assertTrue(ndb.find_ofc_item(nmodels.OFCPort, p))
        port = ndb.find_ofc_item(nmodels.OFCPort, p)
        self.assertEqual(port.id, "ofc-" + p[:-4])

    def testh_exists_ofc_port(self):
        """test exists_ofc_port"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.ofc.create_ofc_network(t, n)
        ndb.add_portinfo(p, "0xabc", 2, 65535, "00:12:22:33:44:55")
        self.assertFalse(self.ofc.exists_ofc_port(p))
        self.ofc.create_ofc_port(t, n, p)
        self.assertTrue(self.ofc.exists_ofc_port(p))

    def testi_delete_ofc_port(self):
        """test delete ofc_port"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.ofc.create_ofc_network(t, n)
        ndb.add_portinfo(p, "0xabc", 3, 65535, "00:13:22:33:44:55")
        self.ofc.create_ofc_port(t, n, p)
        self.assertTrue(ndb.find_ofc_item(nmodels.OFCPort, p))
        self.ofc.delete_ofc_port(t, n, p)
        self.assertFalse(ndb.find_ofc_item(nmodels.OFCPort, p))

    def testj_create_ofc_packet_filter(self):
        """test create ofc_filter"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.ofc.create_ofc_network(t, n)
        self.assertFalse(ndb.find_ofc_item(nmodels.OFCFilter, f))
        self.ofc.create_ofc_packet_filter(t, n, f, {})
        self.assertTrue(ndb.find_ofc_item(nmodels.OFCFilter, f))
        _filter = ndb.find_ofc_item(nmodels.OFCFilter, f)
        self.assertEqual(_filter.id, "ofc-" + f[:-4])

    def testk_exists_ofc_packet_filter(self):
        """test exists_ofc_packet_filter"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.ofc.create_ofc_network(t, n)
        self.assertFalse(self.ofc.exists_ofc_packet_filter(f))
        self.ofc.create_ofc_packet_filter(t, n, f, {})
        self.assertTrue(self.ofc.exists_ofc_packet_filter(f))

    def testl_delete_ofc_packet_filter(self):
        """test delete ofc_filter"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(t)
        self.ofc.create_ofc_network(t, n)
        self.ofc.create_ofc_packet_filter(t, n, f, {})
        self.assertTrue(ndb.find_ofc_item(nmodels.OFCFilter, f))
        self.ofc.delete_ofc_packet_filter(t, n, f)
        self.assertFalse(ndb.find_ofc_item(nmodels.OFCFilter, f))
