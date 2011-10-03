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
# @author: Tyler Smith, Cisco Systems, Inc.
#
"""

import unittest
import logging as LOG

from quantum.common import exceptions as exc
from quantum.plugins.cisco.l2network_plugin import L2Network
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials as creds
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb
from quantum.plugins.cisco.ucs.cisco_ucs_inventory import UCSInventory

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(__name__)

# Set some data to use in tests
tenant = 'shubh'
net_name = 'TestNetwork1'
port_state = const.PORT_UP
interface_id = 'vif-01'


class TestUCSInventory(unittest.TestCase):
    """
    Tests for the UCS Inventory.  Each high-level operation should return
    some information about which devices to perform the action on.
    """

    def setUp(self):
        """Setup our tests"""
        # Initialize cdb and credentials
        db.configure_db({'sql_connection': 'sqlite:///:memory:'})
        cdb.initialize()
        creds.Store.initialize()

        # Create the ucs inventory  object
        self._ucs_inventory = UCSInventory()
        self.inventory = self._ucs_inventory._inventory

        # Create a plugin instance to create networks/ports
        self._l2network = L2Network()

    def assertValidUCM(self, ip_address):
        """Asserts that the given ip is in the UCS inventory"""
        if ip_address in self.inventory.keys():
            assert(1)
            return
        assert(0)

    def assertPortNotFound(self, cmd, args):
        """Asserts that the given command raises a PortNotFound exception"""
        cmd = getattr(self._ucs_inventory, cmd)
        self.assertRaises(exc.PortNotFound, cmd, args)

    def _test_get_all_ucms(self, cmd):
        """Runs tests for commands that expect a list of all UCMS"""
        LOG.debug("test_%s - START", cmd)
        results = getattr(self._ucs_inventory, cmd)([])
        self.assertEqual(results[const.DEVICE_IP], self.inventory.keys())
        LOG.debug("test_%s - END", cmd)

    def _test_with_port_creation(self, cmd, params=None):
        """Tests commands that requires a port to exist"""
        LOG.debug("test_%s - START", cmd)
        net = self._l2network.create_network(tenant, net_name)
        port = self._l2network.create_port(tenant, net[const.NET_ID],
                                           port_state, state=port_state)

        args = [tenant, net[const.NET_ID], port[const.PORT_ID]]
        if params is not None:
            args.extend(params)

        ip_address = getattr(self._ucs_inventory, cmd)(args)
        ip_address = ip_address[const.DEVICE_IP][0]
        self.assertValidUCM(ip_address)

        # Clean up created network and port
        try:
            self._l2network.unplug_interface(tenant,
                net[const.NET_ID], port[const.PORT_ID])
        except:
            pass
        self._l2network.delete_port(tenant,
            net[const.NET_ID], port[const.PORT_ID])
        self._l2network.delete_network(tenant, net[const.NET_ID])
        db.clear_db()

        LOG.debug("test_%s - END", cmd)

    def _test_port_not_found(self, cmd, params=None):
        """Tests commands that should raise a PortNotFound exception"""
        # Figure out the correct name of this test
        name = cmd
        if name[-5:] == "_port":
            name += "_not_found"
        else:
            name += "_port_not_found"

        LOG.debug("test_%s - START", name)
        args = [tenant, 1, 1]
        if params is not None:
            args.extend(params)

        self.assertPortNotFound(cmd, args)
        LOG.debug("test_%s - END", name)

    def test_create_port(self):
        """Test that the UCS Inventory returns the correct devices to use"""
        LOG.debug("test_create_port - START")
        results = self._ucs_inventory.create_port([])
        results = results[const.LEAST_RSVD_BLADE_DICT]

        ip_address = results[const.LEAST_RSVD_BLADE_UCSM]
        chassis = results[const.LEAST_RSVD_BLADE_CHASSIS]
        blade = results[const.LEAST_RSVD_BLADE_ID]

        if blade not in self.inventory[ip_address][chassis]:
            self.assertEqual(0, 1)
        self.assertEqual(1, 1)
        LOG.debug("test_create_port - END")

    def test_get_all_networks(self):
        """Test that the UCS Inventory returns the correct devices to use"""
        self._test_get_all_ucms('get_all_networks')

    def test_create_network(self):
        """Test that the UCS Inventory returns the correct devices to use"""
        self._test_get_all_ucms('create_network')

    def test_delete_network(self):
        """Test that the UCS Inventory returns the correct devices to use"""
        self._test_get_all_ucms('delete_network')

    def test_get_network_details(self):
        """Test that the UCS Inventory returns the correct devices to use"""
        self._test_get_all_ucms('get_network_details')

    def test_update_network(self):
        """Test that the UCS Inventory returns the correct devices to use"""
        self._test_get_all_ucms('update_network')

    def test_get_all_ports(self):
        """Test that the UCS Inventory returns the correct devices to use"""
        self._test_get_all_ucms('get_all_ports')

    def test_delete_port(self):
        """Test that the UCS Inventory returns a valid UCM"""
        self._test_with_port_creation('delete_port')

    def test_get_port_details(self):
        """Test that the UCS Inventory returns a valid UCM"""
        self._test_with_port_creation('get_port_details')

    def test_update_port(self):
        """Test that the UCS Inventory returns a valid UCM"""
        self._test_with_port_creation('update_port', [port_state])

    def test_plug_interface(self):
        """Test that the UCS Inventory returns a valid UCM"""
        self._test_with_port_creation('plug_interface', [interface_id])

    def test_unplug_interface(self):
        """Test that the UCS Inventory returns a valid UCM"""
        self._test_with_port_creation('unplug_interface')

    def test_update_port_not_found(self):
        """Test that the UCS Inventory raises a PortNotFound exception"""
        self._test_port_not_found('update_port')

    def test_get_port_details_port_not_found(self):
        """Test that the UCS Inventory raises a PortNotFound exception"""
        self._test_port_not_found('get_port_details')

    def test_plug_interface_port_not_found(self):
        """Test that the UCS Inventory raises a PortNotFound exception"""
        self._test_port_not_found('plug_interface', [interface_id])

    def test_unplug_interface_port_not_found(self):
        """Test that the UCS Inventory raises a PortNotFound exception"""
        self._test_port_not_found('unplug_interface')
