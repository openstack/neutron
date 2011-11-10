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
import logging as LOG

from quantum.common import exceptions as exc
from quantum.common import utils
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials as creds
from quantum.plugins.cisco.models import l2network_multi_blade
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(__name__)


# Set some data to use in tests
tenant_id = "network_admin"
net_name = "TestNetwork1"
new_net_name = "NewTestNetwork1"
net_id = "44"
port_id = "p0005"
port_state = const.PORT_UP
interface_id = "vif-01"
vlan_id = "102"


def vlan_name(id):
    return "q-%svlan" % id


class TestMultiBlade(unittest.TestCase):
    """
    Tests for the multi-blade model for the L2Network plugin
    """
    _plugins = {}
    _inventory = {}

    def setUp(self):
        """Setup our tests"""
        # Initialize cdb and credentials
        db.configure_db({'sql_connection': 'sqlite:///:memory:'})
        cdb.initialize()
        creds.Store.initialize()

        # Create a place a store net and port ids for the druation of the test
        self.net_id = 0
        self.port_id = 0

        # Create the multiblade object
        self._l2network_multiblade = l2network_multi_blade. \
                     L2NetworkMultiBlade()
        self.plugin_key = "quantum.plugins.cisco.ucs.cisco_ucs_plugin" + \
                            ".UCSVICPlugin"

        # Get UCS inventory to make sure all UCSs are affected by tests
        for key in conf.PLUGINS[const.PLUGINS].keys():
            if key in conf.PLUGINS[const.INVENTORY].keys():
                self._inventory[key] = utils.import_object(
                    conf.PLUGINS[const.INVENTORY][key])

        self.ucs_count = self._inventory['ucs_plugin'].\
                             _inventory.__len__()

    def tearDown(self):
        """Tear down our tests"""
        try:
            port = db.port_get(self.net_id, self.port_id)
            self._l2network_multiblade.delete_port([tenant_id, self.net_id,
                                                self.port_id])
        except exc.NetworkNotFound:
            # We won't always have a port to remove
            pass
        except exc.PortNotFound:
            # We won't always have a port to remove
            pass

        try:
            net = db.network_get(self.net_id)
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

        self.assertEqual(networks.__len__(), self.ucs_count)
        for network in networks:
            self.assertEqual(network[const.NET_ID], self.net_id)
            self.assertEqual(network[const.NET_NAME], net_name)

        LOG.debug("test_create_network - END")

    def test_create_networkDNE(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_create_networkDNE - START")

        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_multiblade.create_network,
                          [tenant_id, net_name, net_id,
                           vlan_name(net_id), vlan_id])

        LOG.debug("test_create_networkDNE - END")

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
            self.assertEqual(network[const.NET_NAME], net_name)

        LOG.debug("test_delete_network - END")

    def test_delete_networkDNE(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_delete_networkDNE - START")

        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_multiblade.delete_network,
                          [tenant_id, net_id])

        LOG.debug("test_delete_networkDNE - END")

    def test_update_network(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_update_network - START")

        self.net_id = db.network_create(tenant_id, net_name)[const.UUID]

        self._l2network_multiblade.create_network([tenant_id,
                                                   net_name,
                                                   self.net_id,
                                                   vlan_name(self.net_id),
                                                   vlan_id])

        db.network_update(self.net_id, tenant_id, name=new_net_name)
        networks = self._l2network_multiblade.update_network([tenant_id,
                                                   self.net_id,
                                                   {'name': new_net_name}])

        self.assertEqual(networks.__len__(), self.ucs_count)
        for network in networks:
            self.assertEqual(network[const.NET_ID], self.net_id)
            self.assertEqual(network[const.NET_NAME], new_net_name)
        LOG.debug("test_update_network - END")

    def test_update_networkDNE(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_update_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_multiblade.update_network,
                          [tenant_id, net_id, {'name': new_net_name}])
        LOG.debug("test_update_networkDNE - END")

    def test_get_all_networks(self):
        """Not implemented for this model"""
        pass

    def test_get_network_details(self):
        """Not implemented for this model"""
        pass

    def test_create_port(self):
        """Support for the Quantum core API call"""
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
        """Support for the Quantum core API call"""
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
                                                port_state, self.port_id])

        port = self._l2network_multiblade.delete_port([tenant_id,
                                                self.net_id,
                                                self.port_id])

        self.assertEqual(self.port_id, port[0][const.PORTID])

        # Recreating port so tear down doesn't cause an error
        self.port_id = db.port_create(self.net_id, port_state)[const.UUID]
        self._l2network_multiblade.create_port([tenant_id,
                                                self.net_id,
                                                port_state, self.port_id])

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
        """Support for the Quantum core API call"""
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
                                                port_state, self.port_id])

        interface = self._l2network_multiblade.plug_interface([tenant_id,
                              self.net_id, self.port_id, interface_id])
        port = db.port_set_attachment(self.net_id, self.port_id, interface_id)

        self.assertEqual(self.port_id, interface[0][const.PORTID])
        self.assertEqual(port[const.INTERFACEID], interface_id)
        LOG.debug("test_plug_interface - END")

    def test_plug_interface_networkDNE(self):
        """Support for the Quantum core API call"""
        LOG.debug("test_plug_interface_networkDNE - START")
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
                                                port_state, self.port_id])

        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_multiblade.plug_interface,
                          [tenant_id, net_id, self.port_id, interface_id])

        LOG.debug("test_plug_interface_networkDNE - END")

    def test_plug_interface_portDNE(self):
        """Support for the Quantum core API call"""
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
        """Support for the Quantum core API call"""
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
                                                port_state, self.port_id])

        self._l2network_multiblade.plug_interface([tenant_id, self.net_id,
                                                  self.port_id, interface_id])
        db.port_set_attachment(self.net_id, self.port_id, interface_id)
        interface = self._l2network_multiblade.unplug_interface([tenant_id,
                                            self.net_id, self.port_id])

        self.assertEqual(self.port_id, interface[0][const.PORTID])
        LOG.debug("test_unplug_interface - END")
