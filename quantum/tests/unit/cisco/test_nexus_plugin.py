# Copyright (c) 2012 OpenStack Foundation.
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

import mock

from quantum.db import api as db
from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.nexus import cisco_nexus_plugin_v2
from quantum.tests import base


NEXUS_IP_ADDRESS = '1.1.1.1'
NEXUS_USERNAME = 'username'
NEXUS_PASSWORD = 'password'
HOSTNAME = 'testhost'
INSTANCE = 'testvm'
NEXUS_PORTS = '1/10'
NEXUS_SSH_PORT = '22'
NEXUS_DRIVER = ('quantum.plugins.cisco.nexus.'
                'cisco_nexus_network_driver_v2.CiscoNEXUSDriver')


class TestCiscoNexusPlugin(base.BaseTestCase):

    def setUp(self):
        """
        Set up function
        """
        super(TestCiscoNexusPlugin, self).setUp()
        self.tenant_id = "test_tenant_cisco1"
        self.net_name = "test_network_cisco1"
        self.net_id = 000007
        self.vlan_name = "q-" + str(self.net_id) + "vlan"
        self.vlan_id = 267
        self.second_net_name = "test_network_cisco2"
        self.second_net_id = 000005
        self.second_vlan_name = "q-" + str(self.second_net_id) + "vlan"
        self.second_vlan_id = 265
        self._nexus_switches = {
            (NEXUS_IP_ADDRESS, HOSTNAME): NEXUS_PORTS,
            (NEXUS_IP_ADDRESS, 'ssh_port'): NEXUS_SSH_PORT,
        }
        self._hostname = HOSTNAME

        def new_nexus_init(self):
            self._client = importutils.import_object(NEXUS_DRIVER)
            self._nexus_ip = NEXUS_IP_ADDRESS
            self._nexus_username = NEXUS_USERNAME
            self._nexus_password = NEXUS_PASSWORD
            self._nexus_ports = NEXUS_PORTS
            self._nexus_ssh_port = NEXUS_SSH_PORT
            self.credentials = {
                self._nexus_ip: {
                    'username': self._nexus_username,
                    'password': self._nexus_password
                }
            }
            db.configure_db()

        # Use a mock netconf client
        mock_ncclient = mock.Mock()
        self.patch_obj = mock.patch.dict('sys.modules',
                                         {'ncclient': mock_ncclient})
        self.patch_obj.start()

        with mock.patch.object(cisco_nexus_plugin_v2.NexusPlugin,
                               '__init__', new=new_nexus_init):
            self._cisco_nexus_plugin = cisco_nexus_plugin_v2.NexusPlugin()
            self._cisco_nexus_plugin._nexus_switches = self._nexus_switches

        self.addCleanup(self.patch_obj.stop)

    def test_a_create_network(self):
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
            vlan_name, vlan_id, self._hostname, INSTANCE)
        self.assertEqual(new_net_dict[const.NET_ID], net_id)
        self.assertEqual(new_net_dict[const.NET_NAME], self.net_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_NAME], self.vlan_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_ID], self.vlan_id)

        new_net_dict = self._cisco_nexus_plugin.create_network(
            tenant_id, second_net_name, second_net_id,
            second_vlan_name, second_vlan_id, self._hostname,
            INSTANCE)

        self.assertEqual(new_net_dict[const.NET_ID], second_net_id)
        self.assertEqual(new_net_dict[const.NET_NAME], self.second_net_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_NAME],
                         self.second_vlan_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_ID], self.second_vlan_id)

    def test_b_nexus_delete_port(self):
        """
        Test to clean up second vlan of nexus device
        created by test_create_delete_network. This
        test will fail if it is run individually.
        """
        expected_instance_id = self._cisco_nexus_plugin.delete_port(
            INSTANCE, self.second_vlan_id
        )

        self.assertEqual(expected_instance_id, INSTANCE)
