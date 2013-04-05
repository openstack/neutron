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

from quantum.openstack.common import log as logging
import quantum.plugins.cisco.db.api as db
import quantum.plugins.cisco.db.l2network_db as l2network_db
import quantum.plugins.cisco.db.nexus_db_v2 as nexus_db
from quantum.tests import base


LOG = logging.getLogger(__name__)


class NexusDB(object):
    """Class consisting of methods to call nexus db methods"""
    def get_all_nexusportbindings(self):
        """get all nexus port bindings"""
        bindings = []
        try:
            for bind in nexus_db.get_all_nexusport_bindings():
                LOG.debug("Getting nexus port binding : %s" % bind.port_id)
                bind_dict = {}
                bind_dict["port-id"] = str(bind.port_id)
                bind_dict["vlan-id"] = str(bind.vlan_id)
                bindings.append(bind_dict)
        except Exception, exc:
            LOG.error("Failed to get all bindings: %s" % str(exc))
        return bindings

    def get_nexusportbinding(self, vlan_id):
        """get nexus port binding"""
        binding = []
        try:
            for bind in nexus_db.get_nexusport_binding(vlan_id):
                LOG.debug("Getting nexus port binding : %s" % bind.port_id)
                bind_dict = {}
                bind_dict["port-id"] = str(bind.port_id)
                bind_dict["vlan-id"] = str(bind.vlan_id)
                binding.append(bind_dict)
        except Exception, exc:
            LOG.error("Failed to get all bindings: %s" % str(exc))
        return binding

    def create_nexusportbinding(self, port_id, vlan_id):
        """create nexus port binding"""
        bind_dict = {}
        try:
            res = nexus_db.add_nexusport_binding(port_id, vlan_id)
            LOG.debug("Created nexus port binding : %s" % res.port_id)
            bind_dict["port-id"] = str(res.port_id)
            bind_dict["vlan-id"] = str(res.vlan_id)
            return bind_dict
        except Exception, exc:
            LOG.error("Failed to create nexus binding: %s" % str(exc))

    def delete_nexusportbinding(self, vlan_id):
        """delete nexus port binding"""
        bindings = []
        try:
            bind = nexus_db.remove_nexusport_binding(vlan_id)
            for res in bind:
                LOG.debug("Deleted nexus port binding: %s" % res.vlan_id)
                bind_dict = {}
                bind_dict["port-id"] = res.port_id
                bindings.append(bind_dict)
            return bindings
        except Exception, exc:
            raise Exception("Failed to delete nexus port binding: %s"
                            % str(exc))

    def update_nexusport_binding(self, port_id, new_vlan_id):
        """update nexus port binding"""
        try:
            res = nexus_db.update_nexusport_binding(port_id, new_vlan_id)
            LOG.debug("Updating nexus port binding : %s" % res.port_id)
            bind_dict = {}
            bind_dict["port-id"] = str(res.port_id)
            bind_dict["vlan-id"] = str(res.vlan_id)
            return bind_dict
        except Exception, exc:
            raise Exception("Failed to update nexus port binding vnic: %s"
                            % str(exc))


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
                vlan_dict["vlan-name"] = vlan_bind.vlan_name
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
                LOG.debug("Getting vlan binding for vlan: %s" %
                          vlan_bind.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(vlan_bind.vlan_id)
                vlan_dict["vlan-name"] = vlan_bind.vlan_name
                vlan_dict["net-id"] = str(vlan_bind.network_id)
                vlan.append(vlan_dict)
        except Exception, exc:
            LOG.error("Failed to get vlan binding: %s" % str(exc))
        return vlan

    def create_vlan_binding(self, vlan_id, vlan_name, network_id):
        """Create a vlan binding"""
        vlan_dict = {}
        try:
            res = l2network_db.add_vlan_binding(vlan_id, vlan_name, network_id)
            LOG.debug("Created vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["vlan-name"] = res.vlan_name
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

    def update_vlan_binding(self, network_id, vlan_id, vlan_name):
        """Update a vlan binding"""
        try:
            res = l2network_db.update_vlan_binding(network_id, vlan_id,
                                                   vlan_name)
            LOG.debug("Updating vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["vlan-name"] = res.vlan_name
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
            res = db.network_create(tenant_id, net_name)
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


class NexusDBTest(base.BaseTestCase):
    """Class conisting of nexus DB unit tests"""
    def setUp(self):
        super(NexusDBTest, self).setUp()
        """Setup for nexus db tests"""
        l2network_db.initialize()
        self.addCleanup(db.clear_db)
        self.dbtest = NexusDB()
        LOG.debug("Setup")

    def testa_create_nexusportbinding(self):
        """create nexus port binding"""
        binding1 = self.dbtest.create_nexusportbinding("port1", 10)
        self.assertTrue(binding1["port-id"] == "port1")
        self.tearDown_nexusportbinding()

    def testb_getall_nexusportbindings(self):
        """get all nexus port binding"""
        self.dbtest.create_nexusportbinding("port1", 10)
        self.dbtest.create_nexusportbinding("port2", 10)
        bindings = self.dbtest.get_all_nexusportbindings()
        count = 0
        for bind in bindings:
            if "port" in bind["port-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDown_nexusportbinding()

    def testc_delete_nexusportbinding(self):
        """delete nexus port binding"""
        self.dbtest.create_nexusportbinding("port1", 10)
        self.dbtest.delete_nexusportbinding(10)
        bindings = self.dbtest.get_all_nexusportbindings()
        count = 0
        for bind in bindings:
            if "port " in bind["port-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDown_nexusportbinding()

    def testd_update_nexusportbinding(self):
        """update nexus port binding"""
        binding1 = self.dbtest.create_nexusportbinding("port1", 10)
        binding1 = self.dbtest.update_nexusport_binding(binding1["port-id"],
                                                        20)
        bindings = self.dbtest.get_all_nexusportbindings()
        count = 0
        for bind in bindings:
            if "20" in str(bind["vlan-id"]):
                count += 1
        self.assertTrue(count == 1)
        self.tearDown_nexusportbinding()

    def tearDown_nexusportbinding(self):
        """tear down nexusport binding table"""
        LOG.debug("Tearing Down Nexus port Bindings")
        binds = self.dbtest.get_all_nexusportbindings()
        for bind in binds:
            vlan_id = bind["vlan-id"]
            self.dbtest.delete_nexusportbinding(vlan_id)


class L2networkDBTest(base.BaseTestCase):
    """Class conisting of L2network DB unit tests"""
    def setUp(self):
        """Setup for tests"""
        super(L2networkDBTest, self).setUp()
        l2network_db.initialize()
        self.dbtest = L2networkDB()
        self.quantum = QuantumDB()
        self.addCleanup(db.clear_db)
        LOG.debug("Setup")

    def testa_create_vlanbinding(self):
        """test add vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        self.teardown_vlanbinding()
        self.teardown_network()

    def testb_getall_vlanbindings(self):
        """test get all vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        net2 = self.quantum.create_network("t1", "netid2")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        vlan2 = self.dbtest.create_vlan_binding(20, "vlan2", net2["net-id"])
        self.assertTrue(vlan2["vlan-id"] == "20")
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for vlan in vlans:
            if "vlan" in vlan["vlan-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_vlanbinding()
        self.teardown_network()

    def testc_delete_vlanbinding(self):
        """test delete vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        self.dbtest.delete_vlan_binding(net1["net-id"])
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for vlan in vlans:
            if "vlan " in vlan["vlan-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_vlanbinding()
        self.teardown_network()

    def testd_update_vlanbinding(self):
        """test update vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        vlan1 = self.dbtest.update_vlan_binding(net1["net-id"], 11, "newvlan1")
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for vlan in vlans:
            if "new" in vlan["vlan-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_vlanbinding()
        self.teardown_network()

    def testm_test_vlanids(self):
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

    def teardown_port(self):
        """tearDown Port table"""
        LOG.debug("Tearing Down Port")
        nets = self.quantum.get_all_networks("t1")
        for net in nets:
            netid = net["net-id"]
            ports = self.quantum.get_all_ports(netid)
            for port in ports:
                portid = port["port-id"]
                self.quantum.delete_port(netid, portid)

    def teardown_vlanbinding(self):
        """tearDown VlanBinding table"""
        LOG.debug("Tearing Down Vlan Binding")
        vlans = self.dbtest.get_all_vlan_bindings()
        for vlan in vlans:
            netid = vlan["net-id"]
            self.dbtest.delete_vlan_binding(netid)


class QuantumDBTest(base.BaseTestCase):
    """Class conisting of Quantum DB unit tests"""
    def setUp(self):
        """Setup for tests"""
        super(QuantumDBTest, self).setUp()
        l2network_db.initialize()
        self.addCleanup(db.clear_db)
        self.dbtest = QuantumDB()
        self.tenant_id = "t1"
        LOG.debug("Setup")

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

    def testd_update_network(self):
        """test to update (rename) network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        net = self.dbtest.update_network(self.tenant_id, net1["net-id"],
                                         name="plugin_test1_renamed")
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
        self.assertTrue(port[0]["int-id"] is None)
        self.teardown_network_port()

    def testh_joined_test(self):
        """test to get network and port"""
        net1 = self.dbtest.create_network("t1", "net1")
        port1 = self.dbtest.create_port(net1["net-id"])
        self.assertTrue(port1["net-id"] == net1["net-id"])
        port2 = self.dbtest.create_port(net1["net-id"])
        self.assertTrue(port2["net-id"] == net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        for port in ports:
            net = port["net"]
            LOG.debug("Port id %s Net id %s" % (port["port-id"], net.uuid))
        self.teardown_joined_test()

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

    def teardown_joined_test(self):
        """tearDown for joined Network and Port test"""
        LOG.debug("Tearing Down Network and Ports")
        nets = self.dbtest.get_all_networks("t1")
        for net in nets:
            netid = net["net-id"]
            ports = self.dbtest.get_all_ports(netid)
            for port in ports:
                self.dbtest.delete_port(port["net-id"], port["port-id"])
            self.dbtest.delete_network(netid)
