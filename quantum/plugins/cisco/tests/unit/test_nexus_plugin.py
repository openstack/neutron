# copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
# @author: Shweta Padubidri, Peter Strunk, Cisco Systems, Inc.

import logging
import unittest

from quantum.common import exceptions as exc
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials as creds
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb
from quantum.plugins.cisco.nexus import cisco_nexus_plugin


LOG = logging.getLogger('quantum.tests.test_nexus')


class TestNexusPlugin(unittest.TestCase):

    def setUp(self):
        """
        Set up function
        """
        self.tenant_id = "test_tenant_cisco1"
        self.net_name = "test_network_cisco1"
        self.net_id = 000007
        self.vlan_name = "q-" + str(self.net_id) + "vlan"
        self.vlan_id = 267
        self.second_vlan_id = 265
        self.port_id = "9"
        db.configure_db({'sql_connection': 'sqlite:///:memory:'})
        cdb.initialize()
        creds.Store.initialize()
        self._cisco_nexus_plugin = cisco_nexus_plugin.NexusPlugin()

    def test_create_network(self, net_tenant_id=None, network_name=None,
                            net_vlan_name=None, net_vlan_id=None):
        """
        Tests creation of new Virtual Network.
        """

        LOG.debug("test_create_network - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        if network_name:
            net_name = network_name
        else:
            net_name = self.net_name
        if net_vlan_name:
            vlan_name = net_vlan_name
        else:
            vlan_name = self.vlan_name
        if net_vlan_id:
            vlan_id = net_vlan_id
        else:
            vlan_id = self.vlan_id

        network_created = self.create_network(tenant_id, net_name)
        cdb.add_vlan_binding(vlan_id, vlan_name, network_created["net-id"])
        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, net_name, network_created["net-id"],
            vlan_name, vlan_id)
        self.assertEqual(new_net_dict[const.NET_ID],
                         network_created["net-id"])
        self.assertEqual(new_net_dict[const.NET_NAME], self.net_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_NAME], self.vlan_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_ID], self.vlan_id)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_create_network - END")

    def test_delete_network(self, net_tenant_id=None, network_name=None):
        """
        Tests deletion of a Virtual Network.
        """

        LOG.debug("test_delete_network - START")

        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        if network_name:
            net_name = network_name
        else:
            net_name = self.net_name

        network_created = self.create_network(tenant_id, net_name)
        cdb.add_vlan_binding(self.vlan_id, self.vlan_name,
                             network_created["net-id"])
        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, self.net_name, network_created["net-id"],
            self.vlan_name, self.vlan_id)
        deleted_net_dict = self._cisco_nexus_plugin.delete_network(
            tenant_id, new_net_dict[const.NET_ID])
        self.assertEqual(deleted_net_dict[const.NET_ID],
                         network_created["net-id"])
        LOG.debug("test_delete_network - END")

    def test_delete_network_DNE(self, net_tenant_id=None, net_id='0005'):
        """
        Tests deletion of a Virtual Network when Network does not exist.
        """

        LOG.debug("test_delete_network_DNE - START")

        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id

        self.assertRaises(exc.NetworkNotFound,
                          self._cisco_nexus_plugin.delete_network,
                          tenant_id, net_id)

        LOG.debug("test_delete_network_DNE - END")

    def test_get_network_details(self, net_tenant_id=None, network_name=None):
        """
        Tests displays details of a Virtual Network .
        """

        LOG.debug("test_get_network_details - START")

        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        if network_name:
            net_name = network_name
        else:
            net_name = self.net_name

        network_created = self.create_network(tenant_id, net_name)
        cdb.add_vlan_binding(self.vlan_id, self.vlan_name,
                             network_created["net-id"])
        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, self.net_name, network_created["net-id"],
            self.vlan_name, self.vlan_id)
        check_net_dict = self._cisco_nexus_plugin.get_network_details(
            tenant_id, network_created["net-id"])
        self.assertEqual(check_net_dict[const.NET_ID],
                         network_created["net-id"])
        self.assertEqual(check_net_dict[const.NET_NAME], self.net_name)
        self.assertEqual(check_net_dict[const.NET_VLAN_NAME], self.vlan_name)
        self.assertEqual(check_net_dict[const.NET_VLAN_ID], self.vlan_id)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_get_network_details - END")

    def test_get_networkDNE(self, net_tenant_id=None, net_id='0005'):
        """
        Tests display of a Virtual Network when Network does not exist.
        """

        LOG.debug("test_get_network_details_network_does_not_exist - START")

        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id

        self.assertRaises(exc.NetworkNotFound,
                          self._cisco_nexus_plugin.get_network_details,
                          tenant_id, net_id)

        LOG.debug("test_get_network_details_network_does_not_exist - END")

    def test_update_network(self, new_name="new_network_name",
                            net_tenant_id=None, network_name=None):
        """
        Tests update of a Virtual Network .
        """

        LOG.debug("test_update_network - START")

        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        if network_name:
            net_name = network_name
        else:
            net_name = self.net_name

        network_created = self.create_network(tenant_id, net_name)
        cdb.add_vlan_binding(self.vlan_id, self.vlan_name,
                             network_created["net-id"])
        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, self.net_name, network_created["net-id"],
            self.vlan_name, self.vlan_id)
        rename_net_dict = self._cisco_nexus_plugin.update_network(
            tenant_id, new_net_dict[const.NET_ID], name=new_name)
        self.assertEqual(rename_net_dict[const.NET_NAME], new_name)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_update_network - END")

    def test_update_network_DNE(self, new_name="new_network_name",
                                net_tenant_id=None, network_id='0005'):
        """
        Tests update of a Virtual Network when Network does not exist.
        """

        LOG.debug("test_update_network_DNE - START")

        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        if network_id:
            net_id = network_id
        else:
            net_id = self.net_id

        self.assertRaises(exc.NetworkNotFound,
                          self._cisco_nexus_plugin.update_network,
                          tenant_id, net_id, name=new_name)

        LOG.debug("test_update_network_DNE - END")

    def test_list_all_networks(self, net_tenant_id=None):
        """
        Tests listing of all the Virtual Networks .
        """

        LOG.debug("test_list_all_networks - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id

        network_created = self.create_network(tenant_id, self.net_name)
        cdb.add_vlan_binding(self.vlan_id, self.vlan_name,
                             network_created["net-id"])
        new_net_dict1 = self._cisco_nexus_plugin.create_network(
            tenant_id, self.net_name, network_created["net-id"],
            self.vlan_name, self.vlan_id)
        network_created2 = self.create_network(tenant_id, 'test_network2')
        cdb.add_vlan_binding(self.second_vlan_id, 'second_vlan',
                             network_created2["net-id"])
        new_net_dict2 = self._cisco_nexus_plugin.create_network(
            tenant_id, "New_Network2", network_created2["net-id"],
            "second_vlan", self.second_vlan_id)
        list_net_dict = self._cisco_nexus_plugin.get_all_networks(tenant_id)
        net_temp_list = [new_net_dict1, new_net_dict2]
        self.assertTrue(net_temp_list[0] in list_net_dict)
        self.assertTrue(net_temp_list[1] in list_net_dict)
        self.tearDownNetwork(tenant_id, new_net_dict1[const.NET_ID])
        self.tearDownNetwork(tenant_id, new_net_dict2[const.NET_ID])
        LOG.debug("test_list_all_networks - END")

    def test_get_vlan_id_for_network(self, net_tenant_id=None,
                                     network_name=None):
        """
        Tests retrieval of vlan id for a Virtual Networks .
        """

        LOG.debug("test_get_vlan_id_for_network - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        if network_name:
            net_name = network_name
        else:
            net_name = self.net_name

        network_created = self.create_network(tenant_id, net_name)
        cdb.add_vlan_binding(self.vlan_id, self.vlan_name,
                             network_created["net-id"])
        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, self.net_name, network_created["net-id"],
            self.vlan_name, self.vlan_id)
        result_vlan_id = self._cisco_nexus_plugin._get_vlan_id_for_network(
            tenant_id, network_created["net-id"])
        self.assertEqual(result_vlan_id, self.vlan_id)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_get_vlan_id_for_network - END")

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

    def tearDownNetwork(self, tenant_id, network_dict_id):
        """
        Clean up functions after the tests
        """
        self._cisco_nexus_plugin.delete_network(tenant_id, network_dict_id)

    def tearDown(self):
        """Clear the test environment"""
        # Remove database contents
        db.clear_db()
