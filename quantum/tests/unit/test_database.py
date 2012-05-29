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

import unittest

from quantum.db import api as db
from quantum.tests.unit import database_stubs as db_stubs


class QuantumDBTest(unittest.TestCase):
    """Class consisting of Quantum DB unit tests"""
    def setUp(self):
        """Setup for tests"""
        db.configure_db({'sql_connection': 'sqlite:///:memory:'})
        self.dbtest = db_stubs.QuantumDB()
        self.tenant_id = "t1"

    def tearDown(self):
        """Tear Down"""
        db.clear_db()

    def testa_create_network(self):
        """test to create network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["name"] == "plugin_test1")

    def testb_get_networks(self):
        """test to get all networks"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["name"] == "plugin_test1")
        net2 = self.dbtest.create_network(self.tenant_id, "plugin_test2")
        self.assertTrue(net2["name"] == "plugin_test2")
        nets = self.dbtest.get_all_networks(self.tenant_id)
        count = 0
        for net in nets:
            if "plugin_test" in net["name"]:
                count += 1
        self.assertTrue(count == 2)

    def testc_delete_network(self):
        """test to delete network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["name"] == "plugin_test1")
        self.dbtest.delete_network(net1["id"])
        nets = self.dbtest.get_all_networks(self.tenant_id)
        count = len(nets)
        self.assertTrue(count == 0)

    def testd_update_network(self):
        """test to rename network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["name"] == "plugin_test1")
        net = self.dbtest.update_network(self.tenant_id, net1["id"],
                                         {'name': "plugin_test1_renamed"})
        print net
        self.assertTrue(net["name"] == "plugin_test1_renamed")

    def teste_create_port(self):
        """test to create port"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["id"])
        self.assertTrue(port["net-id"] == net1["id"])

    def testf_get_ports(self):
        """test to get ports"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["id"])
        self.assertTrue(port["net-id"] == net1["id"])
        ports = self.dbtest.get_all_ports(net1["id"])
        count = len(ports)
        self.assertTrue(count == 1)

    def testf_update_port(self):
        """test to update port"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["id"])
        self.dbtest.update_port(port["net-id"],
                                port['id'],
                                state='ACTIVE',
                                interface_id='interface_id1')
        self.assertTrue(port["net-id"] == net1["id"])
        ports = self.dbtest.get_all_ports(net1["id"])
        new_port = ports[0]
        self.assertEqual('ACTIVE', new_port['state'])
        self.assertEqual('interface_id1', new_port['attachment'])

    def testf_delete_port(self):
        """test to delete port"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["id"])
        self.assertTrue(port["net-id"] == net1["id"])
        ports = self.dbtest.get_all_ports(net1["id"])
        for por in ports:
            self.dbtest.delete_port(net1["id"], por["id"])
        ports = self.dbtest.get_all_ports(net1["id"])
        count = len(ports)
        self.assertTrue(count == 0)

    def testg_plug_unplug_interface(self):
        """test to plug/unplug interface"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port1 = self.dbtest.create_port(net1["id"])
        self.dbtest.plug_interface(net1["id"], port1["id"], "vif1.1")
        port = self.dbtest.get_port(net1["id"], port1["id"])
        self.assertTrue(port[0]["attachment"] == "vif1.1")
        self.dbtest.unplug_interface(net1["id"], port1["id"])
        port = self.dbtest.get_port(net1["id"], port1["id"])
        self.assertTrue(port[0]["attachment"] is None)
