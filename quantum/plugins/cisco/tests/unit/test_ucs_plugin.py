#vim: tabstop=4 shiftwidth=4 softtabstop=4
#copyright 2011 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0(the "License"); you may
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
#
import unittest
import logging as LOG
from quantum.common import exceptions as exc
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.ucs import cisco_ucs_plugin
from quantum.plugins.cisco.ucs import cisco_ucs_configuration  as conf

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger("cisco_plugin")


class UCSVICTestPlugin(unittest.TestCase):

    def setUp(self):
        """
        Set up function.
        """

        self.tenant_id = "test_tenant_cisco12"
        self.net_name = "test_network_cisco12"
        self.net_id = 000011
        self.vlan_name = "q-" + str(self.net_id) + "vlan"
        self.vlan_id = 266
        self.port_id = "4"
        self._cisco_ucs_plugin = cisco_ucs_plugin.UCSVICPlugin()

    def test_create_network(self):
        """
        Tests creation of new Virtual Network.
        """
        LOG.debug("UCSVICTestPlugin:_test_create_network() called\n")
        new_net_dict = self._cisco_ucs_plugin.create_network(
                self.tenant_id,        self.net_name, self.net_id,
                self.vlan_name, self.vlan_id)
        self.assertEqual(new_net_dict[const.NET_ID], self.net_id)
        self.assertEqual(new_net_dict[const.NET_NAME], self.net_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_NAME], self.vlan_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_ID], self.vlan_id)
        self.tearDownNetwork(self.tenant_id, self.net_id)

    def test_delete_network(self):
        """
        Tests deletion of  the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("UCSVICTestPlugin:test_delete_network() called\n")
        self._cisco_ucs_plugin.create_network(
            self.tenant_id, self.net_name, self.net_id,
            self.vlan_name, self.vlan_id)
        new_net_dict = self._cisco_ucs_plugin.delete_network(
           self.tenant_id, self.net_id)
        self.assertEqual(new_net_dict[const.NET_ID], self.net_id)

    def test_get_network_details(self):
        """
        Tests the deletion the Virtual Network belonging to a the
        spec
        """
        LOG.debug("UCSVICTestPlugin:test_get_network_details() called\n")
        self._cisco_ucs_plugin.create_network(
            self.tenant_id, self.net_name, self.net_id,
            self.vlan_name, self.vlan_id)
        new_net_dict = self._cisco_ucs_plugin.get_network_details(
                            self.tenant_id, self.net_id)
        self.assertEqual(new_net_dict[const.NET_ID], self.net_id)
        self.assertEqual(new_net_dict[const.NET_VLAN_NAME], self.vlan_name)
        self.assertEqual(new_net_dict[const.NET_VLAN_ID], self.vlan_id)
        self.tearDownNetwork(self.tenant_id, self.net_id)

    def test_get_all_networks(self):
        """
        Tests whether  dictionary is returned containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug("UCSVICTestPlugin:test_get_all_networks() called\n")
        new_net_dict1 = self._cisco_ucs_plugin.create_network(
             self.tenant_id, self.net_name, self.net_id,
             self.vlan_name, self.vlan_id)
        new_net_dict2 = self._cisco_ucs_plugin.create_network(
                              self.tenant_id, "test_network2",
                              000006, "q-000006vlan", "6")
        net_list = self._cisco_ucs_plugin.get_all_networks(self.tenant_id)
        net_id_list = [new_net_dict1, new_net_dict2]
        self.assertTrue(net_list[0] in net_id_list)
        self.assertTrue(net_list[1] in net_id_list)
        self.tearDownNetwork(self.tenant_id, new_net_dict1[const.NET_ID])
        self.tearDownNetwork(self.tenant_id, new_net_dict2[const.NET_ID])

    def test_get_all_ports(self):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("UCSVICPlugin:get_all_ports() called\n")
        new_net_dict = self._cisco_ucs_plugin.create_network(
             self.tenant_id, self.net_name, self.net_id,
             self.vlan_name, self.vlan_id)
        port_dict1 = self._cisco_ucs_plugin.create_port(
             self.tenant_id, self.net_id, const.PORT_UP,
             self.port_id)
        port_dict2 = self._cisco_ucs_plugin.create_port(
             self.tenant_id, self.net_id,
             const.PORT_UP, "10")
        ports_on_net = self._cisco_ucs_plugin.get_all_ports(
                           self.tenant_id, self.net_id)
        port_list = [port_dict1, port_dict2]
        self.assertTrue(port_list[0] in ports_on_net)
        self.assertTrue(port_list[1] in ports_on_net)
        self._cisco_ucs_plugin.delete_port(self.tenant_id, self.net_id,
                                                self.port_id)
        self.tearDownNetworkPort(self.tenant_id, new_net_dict[const.NET_ID],
                                 port_dict2[const.PORT_ID])

    def _test_rename_network(self, new_name):
        """
        Tests whether symbolic name is updated for the particular
        Virtual Network.
        """
        LOG.debug("UCSVICTestPlugin:_test_rename_network() called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                                   self.net_id, self.vlan_name,
                                              self.vlan_id)
        new_net_dict = self._cisco_ucs_plugin.rename_network(
             self.tenant_id, self.net_id, new_name)
        self.assertEqual(new_net_dict[const.NET_NAME], new_name)
        self.tearDownNetwork(self.tenant_id, self.net_id)

    def test_rename_network(self):
        """
        Tests rename network.
        """
        self._test_rename_network("new_test_network1")

    def _test_create_port(self, port_state):
        """
        Tests creation of a port on the specified Virtual Network.
        """
        LOG.debug("UCSVICTestPlugin:_test_create_port() called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                                  self.net_id, self.vlan_name,
                                              self.vlan_id)
        new_port_dict = self._cisco_ucs_plugin.create_port(
             self.tenant_id, self.net_id, port_state, self.port_id)
        self.assertEqual(new_port_dict[const.PORT_ID], self.port_id)
        self.assertEqual(new_port_dict[const.PORT_STATE], port_state)
        self.assertEqual(new_port_dict[const.ATTACHMENT], None)
        profile_name = self._cisco_ucs_plugin._get_profile_name(self.port_id)
        new_port_profile = new_port_dict[const.PORT_PROFILE]
        self.assertEqual(new_port_profile[const.PROFILE_NAME], profile_name)
        self.assertEqual(new_port_profile[const.PROFILE_VLAN_NAME],
                         conf.DEFAULT_VLAN_NAME)
        self.assertEqual(new_port_profile[const.PROFILE_VLAN_ID],
                         conf.DEFAULT_VLAN_ID)
        self.tearDownNetworkPort(self.tenant_id, self.net_id, self.port_id)

    def test_create_port(self):
        """
        Tests create port.
        """
        self._test_create_port(const.PORT_UP)

    def _test_delete_port(self, port_state):
        """
        Tests Deletion of a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface should first be un-plugged and
        then the port can be deleted.
        """
        LOG.debug("UCSVICTestPlugin:_test_delete_port() called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                               self.net_id, self.vlan_name,
                                               self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                                port_state, self.port_id)
        self._cisco_ucs_plugin.delete_port(self.tenant_id, self.net_id,
                                                self.port_id)
        net = self._cisco_ucs_plugin._get_network(self.tenant_id, self.net_id)
        self.assertEqual(net[const.NET_PORTS], {})
        self.tearDownNetwork(self.tenant_id, self.net_id)

    def test_delete_port(self):
        """
        Tests delete port.
        """
        self._test_delete_port(const.PORT_UP)

    def _test_update_port(self, port_state):
        """
        Tests Updation of the state of a port on the specified Virtual Network.
        """
        LOG.debug("UCSVICTestPlugin:_test_update_port() called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                                   self.net_id, self.vlan_name,
                                              self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                                port_state, self.port_id)
        port = self._cisco_ucs_plugin.update_port(
             self.tenant_id, self.net_id,
             self.port_id, port_state)
        self.assertEqual(port[const.PORT_STATE], port_state)
        self.tearDownNetworkPort(self.tenant_id, self.net_id, self.port_id)

    def test_update_port_state_up(self):
        """
        Tests update port state up
        """
        self._test_update_port(const.PORT_UP)

    def test_update_port_state_down(self):
        """
        Tests update port state down
        """
        self._test_update_port(const.PORT_DOWN)

    def _test_get_port_details_state_up(self, port_state):
        """
        Tests whether  user is able  to retrieve a remote interface
        that is attached to this particular port when port state is Up.
        """
        LOG.debug("UCSVICTestPlugin:_test_get_port_details_state_up()" +
             "called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                               self.net_id, self.vlan_name,
                                               self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                           port_state, self.port_id)
        port = self._cisco_ucs_plugin.get_port_details(
              self.tenant_id, self.net_id, self.port_id)
        self.assertEqual(port[const.PORT_ID], self.port_id)
        self.assertEqual(port[const.PORT_STATE], port_state)
        self.assertEqual(port[const.ATTACHMENT], None)
        new_port_profile = port[const.PORT_PROFILE]
        profile_name = self._cisco_ucs_plugin._get_profile_name(self.port_id)
        self.assertEqual(new_port_profile[const.PROFILE_VLAN_NAME],
                         conf.DEFAULT_VLAN_NAME)
        self.assertEqual(new_port_profile[const.PROFILE_VLAN_ID],
                         conf.DEFAULT_VLAN_ID)
        self.assertEqual(new_port_profile[const.PROFILE_NAME], profile_name)
        self.tearDownNetworkPort(self.tenant_id, self.net_id, self.port_id)

    def _test_show_port_state_down(self, port_state):
        """
        Tests whether  user is able  to retrieve a remote interface
        that is attached to this particular port when port state is down.
        """
        LOG.debug("UCSVICTestPlugin:_test_show_port_state_down()" +
             "called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                               self.net_id, self.vlan_name,
                                               self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                           port_state, self.port_id)
        port = self._cisco_ucs_plugin.get_port_details(self.tenant_id,
                                                           self.net_id,
                                                       self.port_id)
        self.assertEqual(port[const.PORT_ID], self.port_id)
        self.assertNotEqual(port[const.PORT_STATE], port_state)
        self.assertEqual(port[const.ATTACHMENT], None)
        new_port_profile = port[const.PORT_PROFILE]
        profile_name = self._cisco_ucs_plugin._get_profile_name(self.port_id)
        self.assertEqual(new_port_profile[const.PROFILE_VLAN_NAME],
                              conf.DEFAULT_VLAN_NAME)
        self.assertEqual(new_port_profile[const.PROFILE_VLAN_ID],
                         conf.DEFAULT_VLAN_ID)
        self.assertEqual(new_port_profile[const.PROFILE_NAME], profile_name)
        self.tearDownNetworkPort(self.tenant_id, self.net_id, self.port_id)

    def test_get_port_details_state_up(self):
        """
        Tests get port details state up
        """
        self._test_get_port_details_state_up(const.PORT_UP)

    def test_show_port_state_down(self):
        """
        Tests show port state down
        """
        self._test_show_port_state_down(const.PORT_DOWN)

    def test_create_port_profile(self):
        """
        Tests create port profile
        """
        LOG.debug("UCSVICTestPlugin:test_create_port_profile() called\n")
        new_port_profile = self._cisco_ucs_plugin._create_port_profile(
                                self.tenant_id, self.net_id, self.port_id,
                                self.vlan_name, self.vlan_id)
        profile_name = self._cisco_ucs_plugin._get_profile_name(self.port_id)
        self.assertEqual(new_port_profile[const.PROFILE_NAME], profile_name)
        self.assertEqual(new_port_profile[const.PROFILE_VLAN_NAME],
                              self.vlan_name)
        self.assertEqual(new_port_profile[const.PROFILE_VLAN_ID], self.vlan_id)
        self._cisco_ucs_plugin._delete_port_profile(self.port_id, profile_name)

    def test_delete_port_profile(self):
        """
        Tests delete port profile
        """
        LOG.debug("UCSVICTestPlugin:test_delete_port_profile() called\n")
        self._cisco_ucs_plugin._create_port_profile(
                self.tenant_id, self.net_id, self.port_id, self.vlan_name,
                self.vlan_id)
        profile_name = self._cisco_ucs_plugin._get_profile_name(self.port_id)
        counter1 = self._cisco_ucs_plugin._port_profile_counter
        self._cisco_ucs_plugin._delete_port_profile(self.port_id,
                                                         profile_name)
        counter2 = self._cisco_ucs_plugin._port_profile_counter
        self.assertNotEqual(counter1, counter2)

    def _test_plug_interface(self, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        LOG.debug("UCSVICTestPlugin:_test_plug_interface() called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                              self.net_id, self.vlan_name,
                                              self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                                const.PORT_UP, self.port_id)
        self._cisco_ucs_plugin.plug_interface(self.tenant_id, self.net_id,
                                                   self.port_id,
                                              remote_interface_id)
        port = self._cisco_ucs_plugin._get_port(
             self.tenant_id, self.net_id, self.port_id)
        self.assertEqual(port[const.ATTACHMENT], remote_interface_id)
        port_profile = port[const.PORT_PROFILE]
        new_vlan_name = self._cisco_ucs_plugin._get_vlan_name_for_network(
             self.tenant_id, self.net_id)
        new_vlan_id = self._cisco_ucs_plugin._get_vlan_id_for_network(
             self.tenant_id, self.net_id)
        self.assertEqual(port_profile[const.PROFILE_VLAN_NAME], new_vlan_name)
        self.assertEqual(port_profile[const.PROFILE_VLAN_ID], new_vlan_id)
        self.tearDownNetworkPortInterface(self.tenant_id, self.net_id,
                                          self.port_id)

    def test_plug_interface(self):
        """
        Tests test plug interface
        """
        self._test_plug_interface("4")

    def _test_unplug_interface(self, remote_interface_id):
        """
        Tests whether remote interface detaches from the specified port on the
        specified Virtual Network.
        """
        LOG.debug("UCSVICTestPlugin:_test_unplug_interface() called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                              self.net_id, self.vlan_name,
                                              self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                                const.PORT_UP, self.port_id)
        self._cisco_ucs_plugin.plug_interface(self.tenant_id, self.net_id,
                                                   self.port_id,
                                              remote_interface_id)
        self._cisco_ucs_plugin.unplug_interface(self.tenant_id, self.net_id,
                                                self.port_id)
        port = self._cisco_ucs_plugin._get_port(
             self.tenant_id, self.net_id, self.port_id)
        self.assertEqual(port[const.ATTACHMENT], None)
        port_profile = port[const.PORT_PROFILE]
        self.assertEqual(port_profile[const.PROFILE_VLAN_NAME],
                              conf.DEFAULT_VLAN_NAME)
        self.assertEqual(port_profile[const.PROFILE_VLAN_ID],
                          conf.DEFAULT_VLAN_ID)
        self.tearDownNetworkPort(self.tenant_id, self.net_id, self.port_id)

    def test_unplug_interface(self):
        """
        Tests unplug interface
        """
        self._test_unplug_interface("4")

    def test_get_vlan_name_for_network(self):
        """
        Tests get vlan name for network
        """
        LOG.debug("UCSVICTestPlugin:test_get_vlan_name_for_network() called\n")
        net = self._cisco_ucs_plugin.create_network(
             self.tenant_id, self.net_name, self.net_id,
             self.vlan_name, self.vlan_id)
        self.assertEqual(net[const.NET_VLAN_NAME], self.vlan_name)
        self.tearDownNetwork(self.tenant_id, self.net_id)

    def test_get_vlan_id_for_network(self):
        """
        Tests get vlan id for network
        """
        LOG.debug("UCSVICTestPlugin:test_get_vlan_id_for_network() called\n")
        net = self._cisco_ucs_plugin.create_network(
             self.tenant_id, self.net_name, self.net_id, self.vlan_name,
             self.vlan_id)
        self.assertEqual(net[const.NET_VLAN_ID], self.vlan_id)
        self.tearDownNetwork(self.tenant_id, self.net_id)

    def test_get_network(self):
        """
        Tests get network
        """
        LOG.debug("UCSVICTestPlugin:test_get_network() called\n")
        net = self._cisco_ucs_plugin.create_network(
             self.tenant_id, self.net_name, self.net_id, self.vlan_name,
             self.vlan_id)
        self.assertEqual(net[const.NET_ID], self.net_id)
        self.tearDownNetwork(self.tenant_id, self.net_id)

    def test_get_port(self):
        """
        Tests get port
        """
        LOG.debug("UCSVICTestPlugin:test_get_port() called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                                   self.net_id, self.vlan_name,
                                              self.vlan_id)
        new_port_dict = self._cisco_ucs_plugin.create_port(
             self.tenant_id, self.net_id,
             const.PORT_UP, self.port_id)
        self.assertEqual(new_port_dict[const.PORT_ID], self.port_id)
        self.tearDownNetworkPort(self.tenant_id, self.net_id, self.port_id)

    def test_get_network_NetworkNotFound(self):
        """
        Tests get network not found
        """
        self.assertRaises(exc.NetworkNotFound,
                          self._cisco_ucs_plugin._get_network,
                          self.tenant_id, self.net_id)

    def test_delete_network_NetworkNotFound(self):
        """
        Tests delete network not found
        """
        self.assertRaises(exc.NetworkNotFound,
                          self._cisco_ucs_plugin.delete_network,
                          self.tenant_id, self.net_id)

    def test_delete_port_PortInUse(self):
        """
        Tests delete port in use
        """
        self._test_delete_port_PortInUse("4")

    def _test_delete_port_PortInUse(self, remote_interface_id):
        """
        Tests delete port in use
        """
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                               self.net_id, self.vlan_name,
                                               self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                                const.PORT_UP, self.port_id)
        self._cisco_ucs_plugin.plug_interface(self.tenant_id, self.net_id,
                                              self.port_id,
                                              remote_interface_id)
        self.assertRaises(exc.PortInUse, self._cisco_ucs_plugin.delete_port,
                               self.tenant_id, self.net_id, self.port_id)
        self.tearDownNetworkPortInterface(self.tenant_id, self.net_id,
                                               self.port_id)

    def test_delete_port_PortNotFound(self):
        """
        Tests delete port not found
        """
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                                   self.net_id, self.vlan_name,
                                              self.vlan_id)
        self.assertRaises(exc.PortNotFound, self._cisco_ucs_plugin.delete_port,
                               self.tenant_id, self.net_id, self.port_id)
        self.tearDownNetwork(self.tenant_id, self.net_id)

    def test_plug_interface_PortInUse(self):
        """
        Tests plug interface port in use
        """
        self._test_plug_interface_PortInUse("6", "5")

    def _test_plug_interface_PortInUse(self, remote_interface_id1,
                                       remote_interface_id2):
        """
        Tests plug interface port in use
        """
        LOG.debug("UCSVICTestPlugin:_test_plug_interface_PortInUse() called\n")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                              self.net_id, self.vlan_name,
                                              self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                           const.PORT_UP, self.port_id)
        self._cisco_ucs_plugin.plug_interface(self.tenant_id, self.net_id,
                                              self.port_id,
                                              remote_interface_id1)
        self.assertRaises(exc.PortInUse, self._cisco_ucs_plugin.plug_interface,
                          self.tenant_id, self.net_id, self.port_id,
                          remote_interface_id2)
        self.tearDownNetworkPortInterface(self.tenant_id, self.net_id,
                                          self.port_id)

    def test_attachment_exists(self):
        """
        Tests attachment exists
        """
        LOG.debug("UCSVICTestPlugin:testValidateAttachmentAlreadyAttached")
        self._test_attachment_exists("4")

    def _test_attachment_exists(self, remote_interface_id):
        """
        Tests attachment exists
        """
        LOG.debug("UCSVICTestPlugin:_test_validate_attachmentAlreadyAttached")
        self._cisco_ucs_plugin.create_network(self.tenant_id, self.net_name,
                                              self.net_id, self.vlan_name,
                                              self.vlan_id)
        self._cisco_ucs_plugin.create_port(self.tenant_id, self.net_id,
                                           const.PORT_UP, self.port_id)
        self._cisco_ucs_plugin.plug_interface(self.tenant_id, self.net_id,
                                              self.port_id,
                                              remote_interface_id)
        self.assertRaises(
            exc.PortInUse, self._cisco_ucs_plugin._validate_attachment,
            self.tenant_id, self.net_id, self.port_id, remote_interface_id)
        self.tearDownNetworkPortInterface(self.tenant_id, self.net_id,
                                          self.port_id)

    def tearDownNetwork(self, tenant_id, net_id):
        """
        Tear down network
        """
        self._cisco_ucs_plugin.delete_network(tenant_id, net_id)

    def tearDownNetworkPort(self, tenant_id, net_id, port_id):
        """
        Tear down network port
        """
        self._cisco_ucs_plugin.delete_port(tenant_id, net_id,
                                           port_id)
        self.tearDownNetwork(tenant_id, net_id)

    def tearDownNetworkPortInterface(self, tenant_id, net_id, port_id):
        """
        Tear down network port interface
        """
        self._cisco_ucs_plugin.unplug_interface(tenant_id, net_id,
                                                port_id)
        self.tearDownNetworkPort(tenant_id, net_id, port_id)
