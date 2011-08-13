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

import ConfigParser
import os
import logging as LOG
import unittest

from optparse import OptionParser
from quantum.plugins.cisco.common import cisco_constants as const

import quantum.plugins.cisco.db.api as db
import quantum.plugins.cisco.db.l2network_db as l2network_db
import quantum.plugins.cisco.db.l2network_models


LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class L2networkDB(object):
    def get_all_vlan_bindings(self):
        vlans = []
        try:
            for x in l2network_db.get_all_vlan_bindings():
                LOG.debug("Getting vlan bindings for vlan: %s" % x.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(x.vlan_id)
                vlan_dict["vlan-name"] = x.vlan_name
                vlan_dict["net-id"] = str(x.network_id)
                vlans.append(vlan_dict)
        except Exception, e:
            LOG.error("Failed to get all vlan bindings: %s" % str(e))
        return vlans

    def get_vlan_binding(self, network_id):
        vlan = []
        try:
            for x in l2network_db.get_vlan_binding(network_id):
                LOG.debug("Getting vlan binding for vlan: %s" % x.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(x.vlan_id)
                vlan_dict["vlan-name"] = x.vlan_name
                vlan_dict["net-id"] = str(x.network_id)
                vlan.append(vlan_dict)
        except Exception, e:
            LOG.error("Failed to get vlan binding: %s" % str(e))
        return vlan

    def create_vlan_binding(self, vlan_id, vlan_name, network_id):
        vlan_dict = {}
        try:
            res = l2network_db.add_vlan_binding(vlan_id, vlan_name, network_id)
            LOG.debug("Created vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["vlan-name"] = res.vlan_name
            vlan_dict["net-id"] = str(res.network_id)
            return vlan_dict
        except Exception, e:
            LOG.error("Failed to create vlan binding: %s" % str(e))

    def delete_vlan_binding(self, network_id):
        try:
            res = l2network_db.remove_vlan_binding(network_id)
            LOG.debug("Deleted vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            return vlan_dict
        except Exception, e:
            raise Exception("Failed to delete vlan binding: %s" % str(e))

    def update_vlan_binding(self, network_id, vlan_id, vlan_name):
        try:
            res = l2network_db.update_vlan_binding(network_id, vlan_id, \
                                                            vlan_name)
            LOG.debug("Updating vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["vlan-name"] = res.vlan_name
            vlan_dict["net-id"] = str(res.network_id)
            return vlan_dict
        except Exception, e:
            raise Exception("Failed to update vlan binding: %s" % str(e))

    def get_all_portprofiles(self):
        pps = []
        try:
            for x in l2network_db.get_all_portprofiles():
                LOG.debug("Getting port profile : %s" % x.uuid)
                pp_dict = {}
                pp_dict["portprofile-id"] = str(x.uuid)
                pp_dict["portprofile-name"] = x.name
                pp_dict["vlan-id"] = str(x.vlan_id)
                pp_dict["qos"] = x.qos
                pps.append(pp_dict)
        except Exception, e:
            LOG.error("Failed to get all port profiles: %s" % str(e))
        return pps

    def get_portprofile(self, tenant_id, pp_id):
        pp = []
        try:
            for x in l2network_db.get_portprofile(tenant_id, pp_id):
                LOG.debug("Getting port profile : %s" % x.uuid)
                pp_dict = {}
                pp_dict["portprofile-id"] = str(x.uuid)
                pp_dict["portprofile-name"] = x.name
                pp_dict["vlan-id"] = str(x.vlan_id)
                pp_dict["qos"] = x.qos
                pp.append(pp_dict)
        except Exception, e:
            LOG.error("Failed to get port profile: %s" % str(e))
        return pp

    def create_portprofile(self, tenant_id, name, vlan_id, qos):
        pp_dict = {}
        try:
            res = l2network_db.add_portprofile(tenant_id, name, vlan_id, qos)
            LOG.debug("Created port profile: %s" % res.uuid)
            pp_dict["portprofile-id"] = str(res.uuid)
            pp_dict["portprofile-name"] = res.name
            pp_dict["vlan-id"] = str(res.vlan_id)
            pp_dict["qos"] = res.qos
            return pp_dict
        except Exception, e:
            LOG.error("Failed to create port profile: %s" % str(e))

    def delete_portprofile(self, tenant_id, pp_id):
        try:
            res = l2network_db.remove_portprofile(tenant_id, pp_id)
            LOG.debug("Deleted port profile : %s" % res.uuid)
            pp_dict = {}
            pp_dict["pp-id"] = str(res.uuid)
            return pp_dict
        except Exception, e:
            raise Exception("Failed to delete port profile: %s" % str(e))

    def update_portprofile(self, tenant_id, pp_id, name, vlan_id, qos):
        try:
            res = l2network_db.update_portprofile(tenant_id, pp_id, name,
                                                  vlan_id, qos)
            LOG.debug("Updating port profile : %s" % res.uuid)
            pp_dict = {}
            pp_dict["portprofile-id"] = str(res.uuid)
            pp_dict["portprofile-name"] = res.name
            pp_dict["vlan-id"] = str(res.vlan_id)
            pp_dict["qos"] = res.qos
            return pp_dict
        except Exception, e:
            raise Exception("Failed to update port profile: %s" % str(e))

    def get_all_pp_bindings(self):
        pp_bindings = []
        try:
            for x in l2network_db.get_all_pp_bindings():
                LOG.debug("Getting port profile binding: %s" % \
                                               x.portprofile_id)
                ppbinding_dict = {}
                ppbinding_dict["portprofile-id"] = str(x.portprofile_id)
                ppbinding_dict["port-id"] = str(x.port_id)
                ppbinding_dict["tenant-id"] = x.tenant_id
                ppbinding_dict["default"] = x.default
                pp_bindings.append(ppbinding_dict)
        except Exception, e:
            LOG.error("Failed to get all port profiles: %s" % str(e))
        return pp_bindings

    def get_pp_binding(self, tenant_id, pp_id):
        pp_binding = []
        try:
            for x in l2network_db.get_pp_binding(tenant_id, pp_id):
                LOG.debug("Getting port profile binding: %s" % \
                                                 x.portprofile_id)
                ppbinding_dict = {}
                ppbinding_dict["portprofile-id"] = str(x.portprofile_id)
                ppbinding_dict["port-id"] = str(x.port_id)
                ppbinding_dict["tenant-id"] = x.tenant_id
                ppbinding_dict["default"] = x.default
                pp_bindings.append(ppbinding_dict)
        except Exception, e:
            LOG.error("Failed to get port profile binding: %s" % str(e))
        return pp_binding

    def create_pp_binding(self, tenant_id, port_id, pp_id, default):
        ppbinding_dict = {}
        try:
            res = l2network_db.add_pp_binding(tenant_id, port_id, pp_id, \
                                                                default)
            LOG.debug("Created port profile binding: %s" % res.portprofile_id)
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            ppbinding_dict["port-id"] = str(res.port_id)
            ppbinding_dict["tenant-id"] = res.tenant_id
            ppbinding_dict["default"] = res.default
            return ppbinding_dict
        except Exception, e:
            LOG.error("Failed to create port profile binding: %s" % str(e))

    def delete_pp_binding(self, tenant_id, port_id, pp_id):
        try:
            res = l2network_db.remove_pp_binding(tenant_id, port_id, pp_id)
            LOG.debug("Deleted port profile binding : %s" % res.portprofile_id)
            ppbinding_dict = {}
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            return ppbinding_dict
        except Exception, e:
            raise Exception("Failed to delete port profile: %s" % str(e))

    def update_pp_binding(self, tenant_id, pp_id, newtenant_id, \
                          port_id, default):
        try:
            res = l2network_db.update_pp_binding(tenant_id, pp_id,
                                            newtenant_id, port_id, default)
            LOG.debug("Updating port profile binding: %s" % res.portprofile_id)
            ppbinding_dict = {}
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            ppbinding_dict["port-id"] = str(res.port_id)
            ppbinding_dict["tenant-id"] = res.tenant_id
            ppbinding_dict["default"] = res.default
            return ppbinding_dict
        except Exception, e:
            raise Exception("Failed to update portprofile binding:%s" % str(e))


class QuantumDB(object):
    def get_all_networks(self, tenant_id):
        nets = []
        try:
            for x in db.network_list(tenant_id):
                LOG.debug("Getting network: %s" % x.uuid)
                net_dict = {}
                net_dict["tenant-id"] = x.tenant_id
                net_dict["net-id"] = str(x.uuid)
                net_dict["net-name"] = x.name
                nets.append(net_dict)
        except Exception, e:
            LOG.error("Failed to get all networks: %s" % str(e))
        return nets

    def get_network(self, network_id):
        net = []
        try:
            for x in db.network_get(network_id):
                LOG.debug("Getting network: %s" % x.uuid)
                net_dict = {}
                net_dict["tenant-id"] = x.tenant_id
                net_dict["net-id"] = str(x.uuid)
                net_dict["net-name"] = x.name
                nets.append(net_dict)
        except Exception, e:
            LOG.error("Failed to get network: %s" % str(e))
        return net

    def create_network(self, tenant_id, net_name):
        net_dict = {}
        try:
            res = db.network_create(tenant_id, net_name)
            LOG.debug("Created network: %s" % res.uuid)
            net_dict["tenant-id"] = res.tenant_id
            net_dict["net-id"] = str(res.uuid)
            net_dict["net-name"] = res.name
            return net_dict
        except Exception, e:
            LOG.error("Failed to create network: %s" % str(e))

    def delete_network(self, net_id):
        try:
            net = db.network_destroy(net_id)
            LOG.debug("Deleted network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            return net_dict
        except Exception, e:
            raise Exception("Failed to delete port: %s" % str(e))

    def rename_network(self, tenant_id, net_id, new_name):
        try:
            net = db.network_rename(tenant_id, net_id, new_name)
            LOG.debug("Renamed network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            net_dict["net-name"] = net.name
            return net_dict
        except Exception, e:
            raise Exception("Failed to rename network: %s" % str(e))

    def get_all_ports(self, net_id):
        ports = []
        try:
            for x in db.port_list(net_id):
                LOG.debug("Getting port: %s" % x.uuid)
                port_dict = {}
                port_dict["port-id"] = str(x.uuid)
                port_dict["net-id"] = str(x.network_id)
                port_dict["int-id"] = x.interface_id
                port_dict["state"] = x.state
                port_dict["net"] = x.network
                ports.append(port_dict)
            return ports
        except Exception, e:
            LOG.error("Failed to get all ports: %s" % str(e))

    def get_port(self, net_id, port_id):
        port = []
        x = db.port_get(net_id, port_id)
        try:
            LOG.debug("Getting port: %s" % x.uuid)
            port_dict = {}
            port_dict["port-id"] = str(x.uuid)
            port_dict["net-id"] = str(x.network_id)
            port_dict["int-id"] = x.interface_id
            port_dict["state"] = x.state
            port.append(port_dict)
            return port
        except Exception, e:
            LOG.error("Failed to get port: %s" % str(e))

    def create_port(self, net_id):
        port_dict = {}
        try:
            port = db.port_create(net_id)
            LOG.debug("Creating port %s" % port.uuid)
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, e:
            LOG.error("Failed to create port: %s" % str(e))

    def delete_port(self, net_id, port_id):
        try:
            port = db.port_destroy(net_id, port_id)
            LOG.debug("Deleted port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            return port_dict
        except Exception, e:
            raise Exception("Failed to delete port: %s" % str(e))

    def update_port(self, net_id, port_id, port_state):
        try:
            port = db.port_set_state(net_id, port_id, port_state)
            LOG.debug("Updated port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, e:
            raise Exception("Failed to update port state: %s" % str(e))

    def plug_interface(self, net_id, port_id, int_id):
        try:
            port = db.port_set_attachment(net_id, port_id, int_id)
            LOG.debug("Attached interface to port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, e:
            raise Exception("Failed to plug interface: %s" % str(e))

    def unplug_interface(self, net_id, port_id):
        try:
            port = db.port_unset_attachment(net_id, port_id)
            LOG.debug("Detached interface from port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, e:
            raise Exception("Failed to unplug interface: %s" % str(e))


class L2networkDBTest(unittest.TestCase):
    def setUp(self):
        self.dbtest = L2networkDB()
        self.quantum = QuantumDB()
        LOG.debug("Setup")

    def testACreateVlanBinding(self):
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        self.tearDownVlanBinding()
        self.tearDownNetwork()

    def testBGetAllVlanBindings(self):
        net1 = self.quantum.create_network("t1", "netid1")
        net2 = self.quantum.create_network("t1", "netid2")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        vlan2 = self.dbtest.create_vlan_binding(20, "vlan2", net2["net-id"])
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for x in vlans:
            if "vlan" in x["vlan-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownVlanBinding()
        self.tearDownNetwork()

    def testCDeleteVlanBinding(self):
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.dbtest.delete_vlan_binding(net1["net-id"])
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for x in vlans:
            if "vlan " in x["vlan-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownVlanBinding()
        self.tearDownNetwork()

    def testDUpdateVlanBinding(self):
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        vlan1 = self.dbtest.update_vlan_binding(net1["net-id"], 11, "newvlan1")
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for x in vlans:
            if "new" in x["vlan-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownVlanBinding()
        self.tearDownNetwork()

    def testICreatePortProfile(self):
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        self.assertTrue(pp1["portprofile-name"] == "portprofile1")
        self.tearDownPortProfile()
        self.tearDownNetwork()

    def testJGetAllPortProfile(self):
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp2 = self.dbtest.create_portprofile("t1", "portprofile2", 20, "qos2")
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for x in pps:
            if "portprofile" in x["portprofile-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownPortProfile()

    def testKDeletePortProfile(self):
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        self.dbtest.delete_portprofile("t1", pp1["portprofile-id"])
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for x in pps:
            if "portprofile " in x["portprofile-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownPortProfile()

    def testLUpdatePortProfile(self):
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp1 = self.dbtest.update_portprofile("t1", pp1["portprofile-id"], \
                                          "newportprofile1", 20, "qos2")
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for x in pps:
            if "new" in x["portprofile-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownPortProfile()

    def testMCreatePortProfileBinding(self):
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp_binding1 = self.dbtest.create_pp_binding("t1", port1["port-id"], \
                                              pp1["portprofile-id"], "0")
        self.assertTrue(pp_binding1["tenant-id"] == "t1")
        self.tearDownPortProfileBinding()
        self.tearDownPort()
        self.tearDownNetwork()
        self.tearDownPortProfile()

    def testNGetAllPortProfileBinding(self):
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        port2 = self.quantum.create_port(net1["net-id"])
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp2 = self.dbtest.create_portprofile("t1", "portprofile2", 20, "qos2")
        pp_binding1 = self.dbtest.create_pp_binding("t1", port1["port-id"], \
                                               pp1["portprofile-id"], "0")
        pp_binding2 = self.dbtest.create_pp_binding("t1", port2["port-id"], \
                                               pp2["portprofile-id"], "0")
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for x in pp_bindings:
            if "t1" in x["tenant-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownPortProfileBinding()
        self.tearDownPort()
        self.tearDownNetwork()
        self.tearDownPortProfile()

    def testODeletePortProfileBinding(self):
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp_binding1 = self.dbtest.create_pp_binding("t1", port1["port-id"], \
                                                pp1["portprofile-id"], "0")
        self.dbtest.delete_pp_binding("t1", port1["port-id"], \
                                      pp_binding1["portprofile-id"])
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for x in pp_bindings:
            if "t1 " in x["tenant-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownPortProfileBinding()
        self.tearDownPort()
        self.tearDownNetwork()
        self.tearDownPortProfile()

    def testPUpdatePortProfileBinding(self):
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp_binding1 = self.dbtest.create_pp_binding("t1", port1["port-id"], \
                                                pp1["portprofile-id"], "0")
        pp_binding1 = self.dbtest.update_pp_binding("t1", \
                      pp1["portprofile-id"], "newt1", port1["port-id"], "1")
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for x in pp_bindings:
            if "new" in x["tenant-id"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownPortProfileBinding()
        self.tearDownPort()
        self.tearDownNetwork()
        self.tearDownPortProfile()

    def testQtest_vlanids(self):
        l2network_db.create_vlanids()
        vlanids = l2network_db.get_all_vlanids()
        self.assertTrue(len(vlanids) > 0)
        vlanid = l2network_db.reserve_vlanid()
        used = l2network_db.is_vlanid_used(vlanid)
        self.assertTrue(used == True)
        used = l2network_db.release_vlanid(vlanid)
        self.assertTrue(used == False)
        self.tearDownVlanID()

    def tearDownNetwork(self):
        LOG.debug("Tearing Down Network")
        nets = self.quantum.get_all_networks("t1")
        for net in nets:
            id = net["net-id"]
            self.quantum.delete_network(id)

    def tearDownPort(self):
        LOG.debug("Tearing Down Port")
        nets = self.quantum.get_all_networks("t1")
        for net in nets:
            id = net["net-id"]
            ports = self.quantum.get_all_ports(id)
            for port in ports:
                portid = port["port-id"]
                self.quantum.delete_port(id, portid)

    def tearDownVlanBinding(self):
        LOG.debug("Tearing Down Vlan Binding")
        vlans = self.dbtest.get_all_vlan_bindings()
        for vlan in vlans:
            id = vlan["net-id"]
            self.dbtest.delete_vlan_binding(id)

    def tearDownPortProfile(self):
        LOG.debug("Tearing Down Port Profile")
        pps = self.dbtest.get_all_portprofiles()
        for pp in pps:
            id = pp["portprofile-id"]
            self.dbtest.delete_portprofile("t1", id)

    def tearDownPortProfileBinding(self):
        LOG.debug("Tearing Down Port Profile Binding")
        pp_bindings = self.dbtest.get_all_pp_bindings()
        for pp_binding in pp_bindings:
            id = pp_binding["portprofile-id"]
            portid = pp_binding["port-id"]
            self.dbtest.delete_pp_binding("t1", portid, id)

    def tearDownVlanID(self):
        LOG.debug("Tearing Down Vlan IDs")
        vlanids = l2network_db.get_all_vlanids()
        for vlanid in vlanids:
            vlan_id = vlanid["vlan_id"]
            l2network_db.delete_vlanid(vlan_id)


class QuantumDBTest(unittest.TestCase):
    def setUp(self):
        self.dbtest = QuantumDB()
        self.tenant_id = "t1"
        LOG.debug("Setup")

    def testACreateNetwork(self):
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        self.tearDownNetworkPort()

    def testBGetNetworks(self):
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        net2 = self.dbtest.create_network(self.tenant_id, "plugin_test2")
        nets = self.dbtest.get_all_networks(self.tenant_id)
        count = 0
        for x in nets:
            if "plugin_test" in x["net-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownNetworkPort()

    def testCDeleteNetwork(self):
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.dbtest.delete_network(net1["net-id"])
        nets = self.dbtest.get_all_networks(self.tenant_id)
        count = 0
        for x in nets:
            if "plugin_test1" in x["net-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownNetworkPort()

    def testDRenameNetwork(self):
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        net = self.dbtest.rename_network(self.tenant_id, net1["net-id"],
          "plugin_test1_renamed")
        self.assertTrue(net["net-name"] == "plugin_test1_renamed")
        self.tearDownNetworkPort()

    def testECreatePort(self):
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for p in ports:
            count += 1
        self.assertTrue(count == 1)
        self.tearDownNetworkPort()

    def testFDeletePort(self):
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for p in ports:
            count += 1
        self.assertTrue(count == 1)
        for p in ports:
            self.dbtest.delete_port(net1["net-id"], p["port-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for p in ports:
            count += 1
        self.assertTrue(count == 0)
        self.tearDownNetworkPort()

    def testGPlugUnPlugInterface(self):
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port1 = self.dbtest.create_port(net1["net-id"])
        self.dbtest.plug_interface(net1["net-id"], port1["port-id"], "vif1.1")
        port = self.dbtest.get_port(net1["net-id"], port1["port-id"])
        self.assertTrue(port[0]["int-id"] == "vif1.1")
        self.dbtest.unplug_interface(net1["net-id"], port1["port-id"])
        port = self.dbtest.get_port(net1["net-id"], port1["port-id"])
        self.assertTrue(port[0]["int-id"] == None)
        self.tearDownNetworkPort()

    def testIJoinedTest(self):
        net1 = self.dbtest.create_network("t1", "net1")
        port1 = self.dbtest.create_port(net1["net-id"])
        port2 = self.dbtest.create_port(net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        for port in ports:
            net = port["net"]
            LOG.debug("Port id %s Net id %s" % (port["port-id"], net.uuid))
        self.tearDownJoinedTest()

    def tearDownNetworkPort(self):
        networks = self.dbtest.get_all_networks(self.tenant_id)
        for net in networks:
            id = net["net-id"]
            name = net["net-name"]
            if "plugin_test" in name:
                # Clean up any test ports lying around
                ports = self.dbtest.get_all_ports(id)
                for p in ports:
                    self.dbtest.delete_port(id, p["port-id"])
                self.dbtest.delete_network(id)

    def tearDownJoinedTest(self):
        LOG.debug("Tearing Down Network and Ports")
        nets = self.dbtest.get_all_networks("t1")
        for net in nets:
            id = net["net-id"]
            ports = self.dbtest.get_all_ports(id)
            for port in ports:
                self.dbtest.delete_port(port["net-id"], port["port-id"])
            self.dbtest.delete_network(id)


if __name__ == "__main__":
    usagestr = "Usage: %prog [OPTIONS] <command> [args]"
    parser = OptionParser(usage=usagestr)
    parser.add_option("-v", "--verbose", dest="verbose",
      action="store_true", default=False, help="turn on verbose logging")

    options, args = parser.parse_args()

    if options.verbose:
        LOG.basicConfig(level=LOG.DEBUG)
    else:
        LOG.basicConfig(level=LOG.WARN)

    l2network_db.initialize()

    # Run the tests
    suite = unittest.TestLoader().loadTestsFromTestCase(QuantumDBTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
    suite = unittest.TestLoader().loadTestsFromTestCase(L2networkDBTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
