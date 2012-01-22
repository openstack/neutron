"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Cisco Systems, Inc.
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

"""
test_database.py is an independent test suite
that tests the database api method calls
"""
import logging as LOG
import unittest

from common import constants as const

import quantum.db.api as db
import db.l2network_db as l2network_db


LOG.getLogger(__name__)


class L2networkDB(object):

    """Class conisting of methods to call L2network db methods"""
    def get_all_vlan_bindings(self):
        """Get all vlan binding into a list of dict"""
        vlans = []
        try:
            for vlan_bind in l2network_db.get_all_vlan_bindings():
                LOG.debug("Getting vlan bindings for vlan: %s" %
                            vlan_bind.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(vlan_bind.vlan_id)
                vlan_dict["net-id"] = str(vlan_bind.network_id)
                vlans.append(vlan_dict)
        except Exception, exc:
            LOG.error("Failed to get all vlan bindings: %s" % str(exc))
        return vlans

    def get_vlan_binding(self, network_id):
        """Get a vlan binding"""
        vlan = []
        try:
            for vlan_bind in l2network_db.get_vlan_binding(network_id):
                LOG.debug("Getting vlan binding for vlan: %s"
                           % vlan_bind.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(vlan_bind.vlan_id)
                vlan_dict["net-id"] = str(vlan_bind.network_id)
                vlan.append(vlan_dict)
        except Exception, exc:
            LOG.error("Failed to get vlan binding: %s" % str(exc))
        return vlan

    def create_vlan_binding(self, vlan_id, network_id):
        """Create a vlan binding"""
        vlan_dict = {}
        try:
            res = l2network_db.add_vlan_binding(vlan_id, network_id)
            LOG.debug("Created vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["net-id"] = str(res.network_id)
            return vlan_dict
        except Exception, exc:
            LOG.error("Failed to create vlan binding: %s" % str(exc))

    def delete_vlan_binding(self, network_id):
        """Delete a vlan binding"""
        try:
            res = l2network_db.remove_vlan_binding(network_id)
            LOG.debug("Deleted vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            return vlan_dict
        except Exception, exc:
            raise Exception("Failed to delete vlan binding: %s" % str(exc))

    def update_vlan_binding(self, network_id, vlan_id):
        """Update a vlan binding"""
        try:
            res = l2network_db.update_vlan_binding(network_id, vlan_id)
            LOG.debug("Updating vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["net-id"] = str(res.network_id)
            return vlan_dict
        except Exception, exc:
            raise Exception("Failed to update vlan binding: %s" % str(exc))


class QuantumDB(object):
    """Class conisting of methods to call Quantum db methods"""
    def get_all_networks(self, tenant_id):
        """Get all networks"""
        nets = []
        try:
            for net in db.network_list(tenant_id):
                LOG.debug("Getting network: %s" % net.uuid)
                net_dict = {}
                net_dict["tenant-id"] = net.tenant_id
                net_dict["net-id"] = str(net.uuid)
                net_dict["net-name"] = net.name
                nets.append(net_dict)
        except Exception, exc:
            LOG.error("Failed to get all networks: %s" % str(exc))
        return nets

    def get_network(self, network_id):
        """Get a network"""
        net = []
        try:
            for net in db.network_get(network_id):
                LOG.debug("Getting network: %s" % net.uuid)
                net_dict = {}
                net_dict["tenant-id"] = net.tenant_id
                net_dict["net-id"] = str(net.uuid)
                net_dict["net-name"] = net.name
                net.append(net_dict)
        except Exception, exc:
            LOG.error("Failed to get network: %s" % str(exc))
        return net

    def create_network(self, tenant_id, net_name):
        """Create a network"""
        net_dict = {}
        try:
            res = db.network_create(tenant_id,
                                    net_name,
                                    op_status="UP")
            LOG.debug("Created network: %s" % res.uuid)
            net_dict["tenant-id"] = res.tenant_id
            net_dict["net-id"] = str(res.uuid)
            net_dict["net-name"] = res.name
            return net_dict
        except Exception, exc:
            LOG.error("Failed to create network: %s" % str(exc))

    def delete_network(self, net_id):
        """Delete a network"""
        try:
            net = db.network_destroy(net_id)
            LOG.debug("Deleted network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            return net_dict
        except Exception, exc:
            raise Exception("Failed to delete port: %s" % str(exc))

    def update_network(self, tenant_id, net_id, **kwargs):
        """Update a network"""
        try:
            net = db.network_update(net_id, tenant_id, **kwargs)
            LOG.debug("Updated network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            net_dict["net-name"] = net.name
            return net_dict
        except Exception, exc:
            raise Exception("Failed to update network: %s" % str(exc))

    def get_all_ports(self, net_id):
        """Get all ports"""
        ports = []
        try:
            for port in db.port_list(net_id):
                LOG.debug("Getting port: %s" % port.uuid)
                port_dict = {}
                port_dict["port-id"] = str(port.uuid)
                port_dict["net-id"] = str(port.network_id)
                port_dict["int-id"] = port.interface_id
                port_dict["state"] = port.state
                port_dict["net"] = port.network
                ports.append(port_dict)
            return ports
        except Exception, exc:
            LOG.error("Failed to get all ports: %s" % str(exc))

    def get_port(self, net_id, port_id):
        """Get a port"""
        port_list = []
        port = db.port_get(net_id, port_id)
        try:
            LOG.debug("Getting port: %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            port_list.append(port_dict)
            return port_list
        except Exception, exc:
            LOG.error("Failed to get port: %s" % str(exc))

    def create_port(self, net_id):
        """Add a port"""
        port_dict = {}
        try:
            port = db.port_create(net_id)
            LOG.debug("Creating port %s" % port.uuid)
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, exc:
            LOG.error("Failed to create port: %s" % str(exc))

    def delete_port(self, net_id, port_id):
        """Delete a port"""
        try:
            port = db.port_destroy(net_id, port_id)
            LOG.debug("Deleted port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            return port_dict
        except Exception, exc:
            raise Exception("Failed to delete port: %s" % str(exc))

    def update_port(self, net_id, port_id, port_state):
        """Update a port"""
        try:
            port = db.port_set_state(net_id, port_id, port_state)
            LOG.debug("Updated port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, exc:
            raise Exception("Failed to update port state: %s" % str(exc))

    def plug_interface(self, net_id, port_id, int_id):
        """Plug interface to a port"""
        try:
            port = db.port_set_attachment(net_id, port_id, int_id)
            LOG.debug("Attached interface to port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, exc:
            raise Exception("Failed to plug interface: %s" % str(exc))

    def unplug_interface(self, net_id, port_id):
        """Unplug interface to a port"""
        try:
            port = db.port_unset_attachment(net_id, port_id)
            LOG.debug("Detached interface from port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, exc:
            raise Exception("Failed to unplug interface: %s" % str(exc))


class L2networkDBTest(unittest.TestCase):
    """Class conisting of L2network DB unit tests"""
    def setUp(self):
        """Setup for tests"""
        l2network_db.initialize()
        l2network_db.create_vlanids()
        self.dbtest = L2networkDB()
        self.quantum = QuantumDB()
        LOG.debug("Setup")

    def tearDown(self):
        """Tear Down"""
        db.clear_db()

    def testa_create_vlanbinding(self):
        """test add vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        self.teardown_vlanbinding()
        self.teardown_network()

    def testb_getall_vlanbindings(self):
        """test get all vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        net2 = self.quantum.create_network("t1", "netid2")
        vlan1 = self.dbtest.create_vlan_binding(10, net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        vlan2 = self.dbtest.create_vlan_binding(20, net2["net-id"])
        self.assertTrue(vlan2["vlan-id"] == "20")
        vlans = self.dbtest.get_all_vlan_bindings()
        self.assertTrue(len(vlans) == 2)
        self.teardown_vlanbinding()
        self.teardown_network()

    def testc_delete_vlanbinding(self):
        """test delete vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        self.dbtest.delete_vlan_binding(net1["net-id"])
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for vlan in vlans:
            if vlan["vlan-id"] is "10":
                count += 1
        self.assertTrue(count == 0)
        self.teardown_vlanbinding()
        self.teardown_network()

    def testd_update_vlanbinding(self):
        """test update vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        vlan1 = self.dbtest.update_vlan_binding(net1["net-id"], 11)
        self.assertTrue(vlan1["vlan-id"] == "11")
        self.teardown_vlanbinding()
        self.teardown_network()

    def teste_test_vlanids(self):
        """test vlanid methods"""
        l2network_db.create_vlanids()
        vlanids = l2network_db.get_all_vlanids()
        self.assertTrue(len(vlanids) > 0)
        vlanid = l2network_db.reserve_vlanid()
        used = l2network_db.is_vlanid_used(vlanid)
        self.assertTrue(used)
        used = l2network_db.release_vlanid(vlanid)
        self.assertFalse(used)
        #counting on default teardown here to clear db

    def teardown_network(self):
        """tearDown Network table"""
        LOG.debug("Tearing Down Network")
        nets = self.quantum.get_all_networks("t1")
        for net in nets:
            netid = net["net-id"]
            self.quantum.delete_network(netid)

    def teardown_vlanbinding(self):
        """tearDown VlanBinding table"""
        LOG.debug("Tearing Down Vlan Binding")
        vlans = self.dbtest.get_all_vlan_bindings()
        for vlan in vlans:
            netid = vlan["net-id"]
            self.dbtest.delete_vlan_binding(netid)
