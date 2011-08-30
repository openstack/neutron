# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011, Cisco Systems, Inc.
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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

"""
test_database.py is an independent test suite
that tests the database api method calls
"""
import logging
import unittest


from quantum.db import api as db
from tests.unit import database_stubs as db_stubs


LOG = logging.getLogger('quantum.tests.test_database')


class QuantumDBTest(unittest.TestCase):
    """Class conisting of Quantum DB unit tests"""
    def setUp(self):
        """Setup for tests"""
        db.configure_db({'sql_connection': 'sqlite:///:memory:'})
        self.dbtest = db_stubs.QuantumDB()
        self.tenant_id = "t1"
        LOG.debug("Setup")

    def tearDown(self):
        """Tear Down"""
        db.clear_db()

    def testa_create_network(self):
        """test to create network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        self.teardown_network_port()

    def testb_get_networks(self):
        """test to get all networks"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        net2 = self.dbtest.create_network(self.tenant_id, "plugin_test2")
        self.assertTrue(net2["net-name"] == "plugin_test2")
        nets = self.dbtest.get_all_networks(self.tenant_id)
        count = 0
        for net in nets:
            if "plugin_test" in net["net-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_network_port()

    def testc_delete_network(self):
        """test to delete network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        self.dbtest.delete_network(net1["net-id"])
        nets = self.dbtest.get_all_networks(self.tenant_id)
        count = 0
        for net in nets:
            if "plugin_test1" in net["net-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_network_port()

    def testd_rename_network(self):
        """test to rename network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        net = self.dbtest.rename_network(self.tenant_id, net1["net-id"],
          "plugin_test1_renamed")
        self.assertTrue(net["net-name"] == "plugin_test1_renamed")
        self.teardown_network_port()

    def teste_create_port(self):
        """test to create port"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["net-id"])
        self.assertTrue(port["net-id"] == net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for por in ports:
            count += 1
        self.assertTrue(count == 1)
        self.teardown_network_port()

    def testf_delete_port(self):
        """test to delete port"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["net-id"])
        self.assertTrue(port["net-id"] == net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for por in ports:
            count += 1
        self.assertTrue(count == 1)
        for por in ports:
            self.dbtest.delete_port(net1["net-id"], por["port-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for por in ports:
            count += 1
        self.assertTrue(count == 0)
        self.teardown_network_port()

    def testg_plug_unplug_interface(self):
        """test to plug/unplug interface"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port1 = self.dbtest.create_port(net1["net-id"])
        self.dbtest.plug_interface(net1["net-id"], port1["port-id"], "vif1.1")
        port = self.dbtest.get_port(net1["net-id"], port1["port-id"])
        self.assertTrue(port[0]["int-id"] == "vif1.1")
        self.dbtest.unplug_interface(net1["net-id"], port1["port-id"])
        port = self.dbtest.get_port(net1["net-id"], port1["port-id"])
        self.assertTrue(port[0]["int-id"] == None)
        self.teardown_network_port()

    def teardown_network_port(self):
        """tearDown for Network and Port table"""
        networks = self.dbtest.get_all_networks(self.tenant_id)
        for net in networks:
            netid = net["net-id"]
            name = net["net-name"]
            if "plugin_test" in name:
                ports = self.dbtest.get_all_ports(netid)
                for por in ports:
                    self.dbtest.delete_port(netid, por["port-id"])
                self.dbtest.delete_network(netid)
