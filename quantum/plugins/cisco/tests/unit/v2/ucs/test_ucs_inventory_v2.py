# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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

import logging
import unittest
import uuid

from quantum.common import exceptions as exc
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as creds
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco.tests.unit.v2.ucs.cisco_ucs_inventory_fake import (
    UCSInventory,
)


LOG = logging.getLogger(__name__)

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
        cdb.initialize()
        creds.Store.initialize()

        # Create the ucs inventory  object
        self._ucs_inventory = UCSInventory()
        self.inventory = self._ucs_inventory._inventory

    def assertValidUCM(self, ip_address):
        """Asserts that the given ip is in the UCS inventory"""
        if ip_address in self.inventory.keys():
            assert(1)
            return
        assert(0)

    def _test_get_all_ucms(self, cmd):
        """Runs tests for commands that expect a list of all UCMS"""
        LOG.debug("test_%s - START", cmd)
        results = getattr(self._ucs_inventory, cmd)([])
        self.assertEqual(results[const.DEVICE_IP], self.inventory.keys())
        LOG.debug("test_%s - END", cmd)

    def _test_with_port_creation(self, cmd, params=None):
        """Tests commands that requires a port to exist"""
        LOG.debug("test_%s - START", cmd)
        net_uuid = str(uuid.uuid4())
        device_params = self._ucs_inventory.create_port(tenant, net_uuid,
                                                        port_state,
                                                        state=port_state)

        args = [tenant, net_uuid, port[const.PORT_ID]]
        if params is not None:
            args.extend(params)

        ip_address = getattr(self._ucs_inventory, cmd)(args)
        ip_address = ip_address[const.DEVICE_IP][0]
        self.assertValidUCM(ip_address)
        cdb.clear_db()

        LOG.debug("test_%s - END", cmd)

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
