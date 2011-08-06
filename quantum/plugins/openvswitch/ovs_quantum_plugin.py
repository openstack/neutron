# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.

import ConfigParser
import logging as LOG
from optparse import OptionParser
import os
import sys
import unittest

from quantum.common import exceptions as q_exc
from quantum.quantum_plugin_base import QuantumPluginBase

import quantum.db.api as db
import ovs_db

CONF_FILE = "ovs_quantum_plugin.ini"

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger("ovs_quantum_plugin")


def find_config(basepath):
    for root, dirs, files in os.walk(basepath):
        if CONF_FILE in files:
            return os.path.join(root, CONF_FILE)
    return None


class VlanMap(object):
    vlans = {}

    def __init__(self):
        for x in xrange(2, 4094):
            self.vlans[x] = None

    def set(self, vlan_id, network_id):
        self.vlans[vlan_id] = network_id

    def acquire(self, network_id):
        for x in xrange(2, 4094):
            if self.vlans[x] == None:
                self.vlans[x] = network_id
                # LOG.debug("VlanMap::acquire %s -> %s" % (x, network_id))
                return x
        raise Exception("No free vlans..")

    def get(self, vlan_id):
        return self.vlans[vlan_id]

    def release(self, network_id):
        for x in self.vlans.keys():
            if self.vlans[x] == network_id:
                self.vlans[x] = None
                # LOG.debug("VlanMap::release %s" % (x))
                return
        LOG.error("No vlan found with network \"%s\"" % network_id)


class OVSQuantumPlugin(QuantumPluginBase):

    def __init__(self, configfile=None):
        config = ConfigParser.ConfigParser()
        if configfile == None:
            if os.path.exists(CONF_FILE):
                configfile = CONF_FILE
            else:
                configfile = find_config(os.path.abspath(
                        os.path.dirname(__file__)))
        if configfile == None:
            raise Exception("Configuration file \"%s\" doesn't exist" %
              (configfile))
        LOG.debug("Using configuration file: %s" % configfile)
        config.read(configfile)
        LOG.debug("Config: %s" % config)

        DB_NAME = config.get("DATABASE", "name")
        DB_USER = config.get("DATABASE", "user")
        DB_PASS = config.get("DATABASE", "pass")
        DB_HOST = config.get("DATABASE", "host")
        options = {"sql_connection": "mysql://%s:%s@%s/%s" % (DB_USER,
          DB_PASS, DB_HOST, DB_NAME)}
        db.configure_db(options)

        self.vmap = VlanMap()
        # Populate the map with anything that is already present in the
        # database
        vlans = ovs_db.get_vlans()
        for x in vlans:
            vlan_id, network_id = x
            # LOG.debug("Adding already populated vlan %s -> %s"
            #                                   % (vlan_id, network_id))
            self.vmap.set(vlan_id, network_id)

    def get_all_networks(self, tenant_id):
        nets = []
        for x in db.network_list(tenant_id):
            LOG.debug("Adding network: %s" % x.uuid)
            nets.append(self._make_net_dict(str(x.uuid), x.name, None))
        return nets

    def _make_net_dict(self, net_id, net_name, ports):
        res = {'net-id': net_id,
                'net-name': net_name}
        if ports:
            res['net-ports'] = ports
        return res

    def create_network(self, tenant_id, net_name):
        net = db.network_create(tenant_id, net_name)
        LOG.debug("Created network: %s" % net)
        vlan_id = self.vmap.acquire(str(net.uuid))
        ovs_db.add_vlan_binding(vlan_id, str(net.uuid))
        return self._make_net_dict(str(net.uuid), net.name, [])

    def delete_network(self, tenant_id, net_id):
        net = db.network_get(net_id)

        # Verify that no attachments are plugged into the network
        for port in db.port_list(net_id):
            if port['interface_id']:
                raise q_exc.NetworkInUse(net_id=net_id)
        net = db.network_destroy(net_id)
        ovs_db.remove_vlan_binding(net_id)
        self.vmap.release(net_id)
        return self._make_net_dict(str(net.uuid), net.name, [])

    def get_network_details(self, tenant_id, net_id):
        net = db.network_get(net_id)
        ports = self.get_all_ports(tenant_id, net_id)
        return self._make_net_dict(str(net.uuid), net.name, ports)

    def rename_network(self, tenant_id, net_id, new_name):
        net = db.network_rename(net_id, tenant_id, new_name)
        return self._make_net_dict(str(net.uuid), net.name, None)

    def _make_port_dict(self, port_id, port_state, net_id, attachment):
        res = {'port-id': port_id,
               'port-state': port_state}
        if net_id:
            res['net-id'] = net_id
        if attachment:
            res['attachment-id'] = attachment
        return res

    def get_all_ports(self, tenant_id, net_id):
        ids = []
        ports = db.port_list(net_id)
        for p in ports:
            LOG.debug("Appending port: %s" % p.uuid)
            d = self._make_port_dict(str(p.uuid), p.state, None, None)
            ids.append(d)
        return ids

    def create_port(self, tenant_id, net_id, port_state=None):
        LOG.debug("Creating port with network_id: %s" % net_id)
        port = db.port_create(net_id, port_state)
        return self._make_port_dict(str(port.uuid), port.state, None, None)

    def delete_port(self, tenant_id, net_id, port_id):
        port = db.port_destroy(port_id, net_id)
        return self._make_port_dict(str(port.uuid), port.state, None, None)

    def update_port(self, tenant_id, net_id, port_id, port_state):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        LOG.debug("update_port() called\n")
        port = db.port_get(port_id, net_id)
        db.port_set_state(port_id, net_id, port_state)
        return self._make_port_dict(str(port.uuid), port.state, None, None)

    def get_port_details(self, tenant_id, net_id, port_id):
        port = db.port_get(port_id, net_id)
        return self._make_port_dict(str(port.uuid), port.state,
                                port.network_id, port.interface_id)

    def plug_interface(self, tenant_id, net_id, port_id, remote_iface_id):
        db.port_set_attachment(port_id, net_id, remote_iface_id)

    def unplug_interface(self, tenant_id, net_id, port_id):
        db.port_set_attachment(port_id, net_id, "")

    def get_interface_details(self, tenant_id, net_id, port_id):
        res = db.port_get(port_id, net_id)
        return res.interface_id


class VlanMapTest(unittest.TestCase):

    def setUp(self):
        self.vmap = VlanMap()

    def tearDown(self):
        pass

    def testAddVlan(self):
        vlan_id = self.vmap.acquire("foobar")
        self.assertTrue(vlan_id == 2)

    def testReleaseVlan(self):
        vlan_id = self.vmap.acquire("foobar")
        self.vmap.release("foobar")
        self.assertTrue(self.vmap.get(vlan_id) == None)


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

    # Make sqlalchemy quieter
    LOG.getLogger('sqlalchemy.engine').setLevel(LOG.WARN)
    # Run the tests
    suite = unittest.TestLoader().loadTestsFromTestCase(VlanMapTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
