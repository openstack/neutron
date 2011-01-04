"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Shubhangi Satras, Cisco Systems, Inc.
# @author: Peter Strunk, Cisco Systems, Inc.
# @author: Atul Gaikad, Cisco Systems, Inc.
# @author: Tyler Smith, Cisco Systems, Inc.
#
"""

import unittest
from copy import deepcopy
import inspect
import logging as LOG
import platform

from quantum.common import exceptions as exc
from quantum.common import utils
from quantum.plugins.cisco.l2network_model_base import L2NetworkModelBase
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import cisco_credentials as creds
from quantum.plugins.cisco.models import l2network_multi_blade
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb
LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(__name__)


tenant_id = "network_admin"
net_name = "TestNetwork1"
new_net_name = "NewTestNetwork1"
net_id = "44"
port_id = "p0005"
port_state = const.PORT_UP
interface_id = "vif-01"
#vlan_name = "q-%svlan" % net_id
vlan_id = "102"

def vlan_name(id):
    return "q-%svlan" % id

class Test_L2NetworkMultiBlade(unittest.TestCase):
    """
    Implements the L2NetworkModelBase
    This implementation works with UCS and Nexus plugin for the
    following topology:
    One or more UCSM (each with one or more chasses connected)
    All UCSM connected to a single Nexus Switch
    """
    _plugins = {}
    _inventory = {}

    def setUp(self):
        # Initialize cdb and credentials
        db.configure_db({'sql_connection': 'sqlite:///:memory:'})
        cdb.initialize()
        creds.Store.initialize()

        # Set some data to use in tests
        self.tenant_id = "network_admin"
        self.net_name = "TestNetwork1"
        self.profile_name = "test_tenant_port_profile"
        self.port_state = const.PORT_UP
        self.net_id = '44'
        self.net_id_DNE = '458'
        self.port_id = 'p0005'
        self.vlan_name = "q-" + str(self.net_id) + "vlan"
        self.vlan_id = 102
        self.new_net_name="New_test_network"


        self._l2network_multiblade = l2network_multi_blade.\
                     L2NetworkMultiBlade()
        self.plugin_key = "quantum.plugins.cisco.ucs.cisco_ucs_plugin"+\
                            ".UCSVICPlugin"
        self.test_device_ip =  "172.18.117.45"

        for key in conf.PLUGINS[const.PLUGINS].keys():
            self._inventory[key] = utils.import_object(
                conf.PLUGINS[const.INVENTORY][key])

        #for ip in  self._inventory['ucs_plugin']._inventory.keys():
        #    try:
        #        print "tyleertylertyelr"
        #        print cdb.get_credential_name(tenant_id, ip)
        #    except cexc.CredentialNameNotFound:
        #        print 'asdfasdfasdfasdfasdf'
        #        cdb.add_credential(tenant_id, ip,
        #                            creds.Store.getUsername(ip),
        #                            creds.Store.getPassword(ip))
        self.ucs_count = self._inventory['ucs_plugin'].\
                             _inventory.__len__()

    def tearDown(self):
        try:
            self._l2network_multiblade.delete_network([tenant_id, self.net_id])
        except exc.NetworkNotFound:
            # We won't always have a network to remove
            pass
        db.clear_db()

    def test_create_network(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_create_network - START")

        # Create the network in the test DB, then with the model
        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]
        networks = self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])
        cdb.add_vlan_binding(vlan_id, vlan_name(self.net_id), self.net_id)

        self.assertEqual(networks.__len__(), self.ucs_count)        
        for network in networks:
            self.assertEqual(network[const.NET_ID], self.net_id)
            self.assertEqual(network[const.NET_NAME], net_name)

        LOG.debug("test_create_network - END")
    
    def test_delete_network(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_delete_network - START")
        # Create the network in the test DB, then with the model
        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]
        self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])

        cdb.add_vlan_binding(vlan_id, vlan_name(self.net_id), self.net_id)

        networks = self._l2network_multiblade.delete_network([tenant_id,
                                                   self.net_id])

        self.assertEqual(networks.__len__(), self.ucs_count)
        for network in networks:
            self.assertEqual(network[const.NET_ID], self.net_id)
            self.assertEqual(network[const.NET_NAME], self.net_name)

        LOG.debug("test_delete_network - END")

    def test_delete_networkDNE(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_delete_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_multiblade.delete_network,
                          [tenant_id, net_id])
        LOG.debug("test_delete_networkDNE - END")

    def test_rename_network(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_rename_network - START")
        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]
        self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])

        db.network_rename(tenant_id, self.net_id, new_net_name)
        networks = self._l2network_multiblade.rename_network([tenant_id,
                                                   self.net_id,
                                                   new_net_name])

        self.assertEqual(networks.__len__(), self.ucs_count)
        for network in networks:
            self.assertEqual(network[const.NET_ID], self.net_id)
            self.assertEqual(network[const.NET_NAME], new_net_name)
        LOG.debug("test_rename_network - END")

    def test_rename_networkDNE(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_rename_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_multiblade.rename_network,
                          [tenant_id, net_id, new_net_name])
        LOG.debug("test_rename_networkDNE - END")

    def test_get_all_networks(self):
        """Not implemented for this model"""
        pass

    def test_get_network_details(self):
        """Not implemented for this model"""
        pass

    def test_create_port(self):
        LOG.debug("test_create_port - START")
        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]
        self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])

        self.port_id = db.port_create(self.net_id, port_state)[const.UUID]
        port = self._l2network_multiblade.create_port([tenant_id,
                                                self.net_id, 
                                                port_state,
                                                self.port_id])

        self.assertEqual(self.port_id, port[0][const.PORTID])
        LOG.debug("test_create_port - END")
        
    def test_delete_port(self):
        LOG.debug("test_delete_port - START")
        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]
        self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])

        self.port_id = db.port_create(self.net_id, port_state)[const.UUID]
        self._l2network_multiblade.create_port([tenant_id,
                                                self.net_id, 
                                                port_state,self.port_id])
                                                
        port = self._l2network_multiblade.delete_port([tenant_id,
                                                self.net_id, 
                                                self.port_id])

        self.assertEqual(self.port_id, port[0][const.PORTID])
        LOG.debug("test_delete_port - END")

    def test_get_all_ports(self):
        """Not implemented for this model"""
        pass

    def test_update_port(self):
        """Not implemented for this model"""
        pass

    def test_update_portDNE(self):
        """Not implemented for this model"""
        pass

    def test_update_port_networkDNE(self):
        """Not implemented for this model"""
        pass
		
    def test_port_details(self):
        """Not implemented for this model"""
        pass

    def test_plug_interface(self):
        LOG.debug("test_plug_interface - START") 
        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]
        self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])
        cdb.add_vlan_binding(vlan_id, vlan_name(self.net_id), self.net_id)

        self.port_id = db.port_create(self.net_id, port_state)[const.UUID]
        self._l2network_multiblade.create_port([tenant_id,
                                                self.net_id, 
                                                port_state,self.port_id])

        int = self._l2network_multiblade.plug_interface([tenant_id, self.net_id,
                                                  self.port_id, interface_id])
        port = db.port_set_attachment(self.net_id, self.port_id, interface_id)

        self.assertEqual(self.port_id, int[0][const.PORTID])
        self.assertEqual(port[const.INTERFACEID], interface_id)
        LOG.debug("test_plug_interface - END")

    def test_plug_interface_portDNE(self):
        LOG.debug("test_plug_interface_portDNE - START") 
        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]
        self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])
        cdb.add_vlan_binding(vlan_id, vlan_name(self.net_id), self.net_id)

        self.assertRaises(exc.PortNotFound,
                          self._l2network_multiblade.plug_interface,
                          [tenant_id, self.net_id, port_id, interface_id])

        LOG.debug("test_plug_interface_portDNE - START") 

    def test_unplug_interface(self):
        LOG.debug("test_unplug_interface - START") 
        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]
        self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])
        cdb.add_vlan_binding(vlan_id, vlan_name(self.net_id), self.net_id)

        self.port_id = db.port_create(self.net_id, port_state)[const.UUID]
        self._l2network_multiblade.create_port([tenant_id,
                                                self.net_id, 
                                                port_state,self.port_id])

        self._l2network_multiblade.plug_interface([tenant_id, self.net_id,
                                                  self.port_id, interface_id])
        port = db.port_set_attachment(self.net_id, self.port_id, interface_id)
        int = self._l2network_multiblade.unplug_interface([tenant_id, self.net_id,
                                                  self.port_id])

        self.assertEqual(self.port_id, int[0][const.PORTID])
        LOG.debug("test_unplug_interface - END")


