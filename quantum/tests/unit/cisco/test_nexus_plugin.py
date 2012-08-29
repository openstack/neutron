# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import mock
import unittest

from quantum.common import exceptions as exc
from quantum.db import api as db
from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as creds
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco.db import network_models_v2
from quantum.plugins.cisco.nexus import cisco_nexus_plugin_v2


NEXUS_IP_ADDRESS = '1.1.1.1'
NEXUS_USERNAME = 'username'
NEXUS_PASSWORD = 'password'
NEXUS_PORTS = ['1/10']
NEXUS_SSH_PORT = '22'
NEXUS_DRIVER = ('quantum.plugins.cisco.tests.unit.v2.nexus.'
                'fake_nexus_driver.CiscoNEXUSFakeDriver')


class TestCiscoNexusPlugin(unittest.TestCase):

    def setUp(self):
        """
        Set up function
        """
        self.tenant_id = "test_tenant_cisco1"
        self.net_name = "test_network_cisco1"
        self.net_id = 000007
        self.vlan_name = "q-" + str(self.net_id) + "vlan"
        self.vlan_id = 267
        self.second_net_name = "test_network_cisco2"
        self.second_net_id = 000005
        self.second_vlan_name = "q-" + str(self.second_net_id) + "vlan"
        self.second_vlan_id = 265

        def new_cdb_init():
            db.configure_db({'sql_connection': 'sqlite://',
                             'base': network_models_v2.model_base.BASEV2})

        def new_nexus_init(self):
            self._client = importutils.import_object(NEXUS_DRIVER)
            self._nexus_ip = NEXUS_IP_ADDRESS
            self._nexus_username = NEXUS_USERNAME
            self._nexus_password = NEXUS_PASSWORD
            self._nexus_ports = NEXUS_PORTS
            self._nexus_ssh_port = NEXUS_SSH_PORT

        with mock.patch.object(cdb, 'initialize', new=new_cdb_init):
            cdb.initialize()
            with mock.patch.object(cisco_nexus_plugin_v2.NexusPlugin,
                                   '__init__', new=new_nexus_init):
                self._cisco_nexus_plugin = cisco_nexus_plugin_v2.NexusPlugin()

    def test_a_create_delete_network(self):
        """
        Tests creation of two new Virtual Network.
        Tests deletion of one Virtual Network.
        This would result the following -
        The Nexus device should have only one network
        vlan configured on it's plugin configured
        interfaces.
        If running this test individually, run
        test_nexus_clear_vlan after this test to clean
        up the second vlan created by this test.
        """
        tenant_id = self.tenant_id
        net_name = self.net_name
        net_id = self.net_id
        vlan_name = self.vlan_name
        vlan_id = self.vlan_id
        second_net_name = self.second_net_name
        second_net_id = self.second_net_id
        second_vlan_name = self.second_vlan_name
        second_vlan_id = self.second_vlan_id

        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, net_name, net_id,
            vlan_name, vlan_id, vlan_ids=str(vlan_id))

        self.assertEqual(new_net_dict[const.NET_ID], net_id)
        self.assertEqual(new_net_dict[const.NET_NAME], self.net_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_NAME], self.vlan_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_ID], self.vlan_id)

        vlan_ids = str(vlan_id) + "," + str(second_vlan_id)
        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, second_net_name, second_net_id,
            second_vlan_name, second_vlan_id,
            vlan_ids=vlan_ids)

        self.assertEqual(new_net_dict[const.NET_ID], second_net_id)
        self.assertEqual(new_net_dict[const.NET_NAME], self.second_net_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_NAME],
                         self.second_vlan_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_ID], self.second_vlan_id)

        expected_net_id = self._cisco_nexus_plugin.delete_network(
            tenant_id, net_id, vlan_id=str(vlan_id))

        self.assertEqual(expected_net_id, net_id)

    def test_b_nexus_clear_vlan(self):
        """
        Test to clean up second vlan of nexus device
        created by test_create_delete_network. This
        test will fail if it is run individually.
        """
        tenant_id = self.tenant_id
        second_net_id = self.second_net_id
        second_vlan_id = self.second_vlan_id

        expected_second_net_id = self._cisco_nexus_plugin.delete_network(
            tenant_id, second_net_id,
            vlan_id=str(second_vlan_id))

        self.assertEqual(expected_second_net_id, second_net_id)

    def test_c_update_network_False(self):
        """
        Test to update a network state to False
        resulting in disabling a vlan corresponding to
        that network from the configured nexus interfaces
        """
        tenant_id = self.tenant_id
        net_name = self.net_name
        net_id = self.net_id
        vlan_name = self.vlan_name
        vlan_id = self.vlan_id
        second_net_name = self.second_net_name
        second_net_id = self.second_net_id
        second_vlan_name = self.second_vlan_name
        second_vlan_id = self.second_vlan_id

        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, net_name, net_id,
            vlan_name, vlan_id, vlan_ids=str(vlan_id))

        vlan_ids = str(vlan_id) + "," + str(second_vlan_id)
        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, second_net_name, second_net_id,
            second_vlan_name, second_vlan_id,
            vlan_ids=vlan_ids)

        expected_net_id = self._cisco_nexus_plugin.update_network(
            tenant_id, net_id, net_admin_state=False,
            vlan_id=vlan_id, vlan_ids=str(vlan_id))

        self.assertEqual(expected_net_id, net_id)

    def test_d_nexus_clean_vlan_update(self):
        """
        Cleans up vlans on the nexus for the two
        created networks
        """
        tenant_id = self.tenant_id
        net_id = self.net_id
        vlan_id = self.vlan_id
        second_net_id = self.second_net_id
        second_vlan_id = self.second_vlan_id

        netid = self._cisco_nexus_plugin.delete_network(
            tenant_id, net_id, vlan_id=str(vlan_id))

        self.assertEqual(netid, net_id)

        expected_second_net_id = self._cisco_nexus_plugin.delete_network(
            tenant_id, second_net_id,
            vlan_id=str(second_vlan_id))

        self.assertEqual(expected_second_net_id, second_net_id)

    def test_e_update_network_True(self):
        """
        Test to update a disabled network state to True
        resulting in enabling a vlan corresponding to
        that network to the configured nexus interfaces
        """
        tenant_id = self.tenant_id
        net_name = self.net_name
        net_id = self.net_id
        vlan_name = self.vlan_name
        vlan_id = self.vlan_id
        second_vlan_id = self.second_vlan_id

        self.test_c_update_network_False()

        vlan_ids = str(vlan_id) + "," + str(second_vlan_id)
        expected_net_id = self._cisco_nexus_plugin.update_network(
            tenant_id, net_id, net_admin_state=True,
            vlan_id=vlan_id, vlan_ids=str(vlan_ids))

        self.assertEqual(expected_net_id, net_id)

        self.test_d_nexus_clean_vlan_update()

    def tearDown(self):
        """Clear the test environment"""
        # Remove database contents
        db.clear_db(network_models_v2.model_base.BASEV2)
