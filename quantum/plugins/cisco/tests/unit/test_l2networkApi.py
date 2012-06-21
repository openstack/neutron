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
# @author: Shweta Padubidri, Cisco Systems, Inc.
#

import logging
import unittest

from quantum.common import exceptions as exc
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import l2network_db as cdb
from quantum.plugins.cisco import l2network_plugin
from quantum.plugins.cisco import l2network_plugin_configuration as conf


LOG = logging.getLogger('quantum.tests.test_core_api_func')


class CoreAPITestFunc(unittest.TestCase):

    def test_create_network(self, net_tenant_id=None, net_name=None):

        """
        Tests creation of new Virtual Network.
        """

        LOG.debug("test_create_network - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        if net_name:
            network_name = net_name
        else:
            network_name = self.network_name
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, network_name)
        net = db.network_get(new_net_dict[const.NET_ID])
        self.assertEqual(net[const.NETWORKNAME], network_name)
        self.assertEqual(new_net_dict[const.NET_NAME], network_name)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_create_network - END")

    def test_delete_network(self, net_tenant_id=None):
        """
        Tests deletion of a Virtual Network.
        """
        LOG.debug("test_delete_network - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        delete_net_dict = self._l2network_plugin.delete_network(
            tenant_id, new_net_dict[const.NET_ID])
        self.assertRaises(exc.NetworkNotFound, db.network_get,
                          new_net_dict[const.NET_ID])
        self.assertEqual(new_net_dict[const.NET_ID],
                         delete_net_dict[const.NET_ID])
        LOG.debug("test_delete_network - END")

    def test_delete_networkDNE(self, net_tenant_id=None, net_id='0005'):
        """
        Tests deletion of a Virtual Network when Network does not exist.
        """
        LOG.debug("test_delete_network_not_found - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        self.assertRaises(
            exc.NetworkNotFound, self._l2network_plugin.delete_network,
            tenant_id, net_id)
        LOG.debug("test_delete_network_not_found - END")

    def test_delete_networkInUse(self, tenant_id='test_tenant',
                                 instance_tenant_id='nova',
                                 nova_user_id='novaadmin', instance_id=10,
                                 vif_id='fe701ddf-26a2-'
                                        '42ea-b9e6-7313d1c522cc'):

        """
        Tests deletion of a Virtual Network when Network is in Use.
        """
        LOG.debug("test_delete_networkInUse - START")

        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID], self.state)
        instance_desc = {'project_id': tenant_id,
                         'user_id': nova_user_id}
        host_list = self._l2network_plugin.schedule_host(instance_tenant_id,
                                                         instance_id,
                                                         instance_desc)
        instance_vif_desc = {'project_id': tenant_id,
                             'user_id': nova_user_id,
                             'vif_id': vif_id}
        if conf.PLUGINS[const.PLUGINS].keys():
            vif_description = self._l2network_plugin.associate_port(
                instance_tenant_id, instance_id, instance_vif_desc)
        else:
            db.port_set_attachment_by_id(port_dict[const.PORT_ID],
                                         instance_vif_desc['vif_id'] +
                                         const.UNPLUGGED)
        self.assertRaises(exc.NetworkInUse,
                          self._l2network_plugin.delete_network, tenant_id,
                          new_net_dict[const.NET_ID])
        self.tearDownNetworkPortInterface(
            tenant_id, instance_tenant_id, instance_id, instance_vif_desc,
            new_net_dict[const.NET_ID], port_dict[const.PORT_ID])
        LOG.debug("test_delete_networkInUse - END")

    def test_show_network(self, net_tenant_id=None):
        """
        Tests display of details of a Virtual Network .
        """

        LOG.debug("test_show_network - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        result_net_dict = self._l2network_plugin.get_network_details(
            tenant_id, new_net_dict[const.NET_ID])
        net = db.network_get(new_net_dict[const.NET_ID])
        self.assertEqual(net[const.UUID], new_net_dict[const.NET_ID])
        self.assertEqual(new_net_dict[const.NET_ID],
                         result_net_dict[const.NET_ID])
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_show_network - END")

    def test_show_networkDNE(self, net_tenant_id=None, net_id='0005'):
        """
        Tests display of a Virtual Network when Network does not exist.
        """

        LOG.debug("test_show_network_not_found - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_plugin.get_network_details,
                          tenant_id, net_id)
        LOG.debug("test_show_network_not_found - END")

    def test_update_network(self, net_tenant_id=None,
                            new_name='new_test_network'):
        """
        Tests rename of a Virtual Network .
        """

        LOG.debug("test_update_network - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        rename_net_dict = self._l2network_plugin.update_network(
            tenant_id, new_net_dict[const.NET_ID],
            name=new_name)
        net = db.network_get(new_net_dict[const.NET_ID])
        self.assertEqual(net[const.NETWORKNAME], new_name)
        self.assertEqual(new_name, rename_net_dict[const.NET_NAME])
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_update_network - END")

    def test_update_networkDNE(self, net_tenant_id=None,
                               net_id='0005', new_name='new_test_network'):
        """
        Tests update of a Virtual Network when Network does not exist.
        """

        LOG.debug("test_update_network_not_found - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_plugin.update_network,
                          tenant_id, net_id, name=new_name)
        LOG.debug("test_update_network_not_found - END")

    def test_list_networks(self, tenant_id='test_network'):
        """
        Tests listing of all the Virtual Networks .
        """

        LOG.debug("test_list_networks - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        new_net_dict2 = self._l2network_plugin.create_network(
            tenant_id, 'test_net2')
        net_list = self._l2network_plugin.get_all_networks(tenant_id)
        net_temp_list = [new_net_dict, new_net_dict2]
        networks_list = db.network_list(tenant_id)
        new_networks_list = []
        for network in networks_list:
            new_network_dict = self._make_net_dict(network[const.UUID],
                                                   network[const.NETWORKNAME],
                                                   [])
            new_networks_list.append(new_network_dict)
        self.assertEqual(len(net_list), 2)
        self.assertTrue(net_list[0] in net_temp_list)
        self.assertTrue(net_list[1] in net_temp_list)
        self.assertTrue(new_networks_list[0] in net_temp_list)
        self.assertTrue(new_networks_list[1] in net_temp_list)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        self.tearDownNetwork(tenant_id, new_net_dict2[const.NET_ID])
        LOG.debug("test_list_networks - END")

    def test_list_ports(self, tenant_id='test_network'):
        """
        Tests listing of all the Ports.
        """

        LOG.debug("test_list_ports - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            self.state)
        port_dict2 = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            self.state)
        port_list = self._l2network_plugin.get_all_ports(
            tenant_id, new_net_dict[const.NET_ID])
        port_temp_list = [port_dict, port_dict2]
        network = db.network_get(new_net_dict[const.NET_ID])
        ports_list = network[const.NETWORKPORTS]
        ports_on_net = []
        for port in ports_list:
            new_port = self._make_port_dict(port[const.UUID],
                                            port[const.PORTSTATE],
                                            port[const.NETWORKID],
                                            port[const.INTERFACEID])
            ports_on_net.append(new_port)
        self.assertEqual(len(port_list), 2)
        self.assertTrue(port_list[0] in port_temp_list)
        self.assertTrue(port_list[1] in port_temp_list)
        self.assertTrue(ports_on_net[0] in port_temp_list)
        self.assertTrue(ports_on_net[1] in port_temp_list)

        self.tearDownPortOnly(tenant_id, new_net_dict[const.NET_ID],
                              port_dict[const.PORT_ID])
        self.tearDownNetworkPort(tenant_id, new_net_dict[const.NET_ID],
                                 port_dict2[const.PORT_ID])
        LOG.debug("test_list_ports - END")

    def test_create_port(self, tenant_id='test_network',
                         state=const.PORT_UP):
        """
        Tests creation of Ports.
        """

        LOG.debug("test_create_port - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID], state)
        port = db.port_get(new_net_dict[const.NET_ID],
                           port_dict[const.PORT_ID])
        self.assertEqual(port_dict[const.PORT_STATE], state)
        self.assertEqual(port_dict[const.NET_ID], new_net_dict[const.NET_ID])
        self.assertEqual(port[const.PORTSTATE], state)
        self.assertEqual(port[const.NETWORKID], new_net_dict[const.NET_ID])
        self.tearDownNetworkPort(tenant_id, new_net_dict[const.NET_ID],
                                 port_dict[const.PORT_ID])
        LOG.debug("test_create_port - END")

    def test_create_port_network_DNE(
            self, net_tenant_id=None, net_id='0005', state=const.PORT_UP):

        """
        Tests creation of Ports when network does not exist.
        """

        LOG.debug("test_create_port_network_DNE - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_plugin.create_port,
                          tenant_id, net_id, state)
        LOG.debug("test_create_port_network_DNE - END:")

    def test_delete_port(self, tenant_id='test_tenant',
                         state=const.PORT_UP):
        """
        Tests deletion of Ports
        """

        LOG.debug("test_delete_port - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            state)
        delete_port_dict = self._l2network_plugin.delete_port(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID])
        self.assertRaises(exc.PortNotFound, db.port_get,
                          new_net_dict[const.NET_ID], port_dict[const.PORT_ID])
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        self.assertEqual(delete_port_dict[const.PORT_ID],
                         port_dict[const.PORT_ID])
        LOG.debug("test_delete_port - END")

    def test_delete_port_networkDNE(self, tenant_id='test_tenant',
                                    net_id='0005', port_id='p0005'):
        """
        Tests deletion of Ports when network does not exist.
        """

        LOG.debug("test_delete_port_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_plugin.delete_port, tenant_id,
                          net_id, port_id)
        LOG.debug("test_delete_port_networkDNE - END")

    def test_delete_portDNE(self, tenant_id='test_tenant', port_id='p0005'):
        """
        Tests deletion of Ports when port does not exist.
        """

        LOG.debug("test_delete_portDNE - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        self.assertRaises(exc.PortNotFound, self._l2network_plugin.delete_port,
                          tenant_id, new_net_dict[const.NET_ID], port_id)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_delete_portDNE - END")

    def test_delete_portInUse(self,
                              tenant_id='test_tenant',
                              instance_tenant_id='nova',
                              nova_user_id='novaadmin',
                              instance_id=10,
                              vif_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc'):
        """
        Tests deletion of Ports when port is in Use.
        """
        LOG.debug("test_delete_portInUse - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            self.state)
        instance_desc = {'project_id': tenant_id,
                         'user_id': nova_user_id}
        host_list = self._l2network_plugin.schedule_host(instance_tenant_id,
                                                         instance_id,
                                                         instance_desc)
        instance_vif_desc = {'project_id': tenant_id,
                             'user_id': nova_user_id,
                             'vif_id': vif_id}
        if conf.PLUGINS[const.PLUGINS].keys():
            vif_description = self._l2network_plugin.associate_port(
                instance_tenant_id, instance_id, instance_vif_desc)
        else:
            db.port_set_attachment_by_id(port_dict[const.PORT_ID],
                                         instance_vif_desc['vif_id'] +
                                         const.UNPLUGGED)

        self.assertRaises(exc.PortInUse, self._l2network_plugin.delete_port,
                          tenant_id, new_net_dict[const.NET_ID],
                          port_dict[const.PORT_ID])
        self.tearDownNetworkPortInterface(
            tenant_id, instance_tenant_id, instance_id, instance_vif_desc,
            new_net_dict[const.NET_ID], port_dict[const.PORT_ID])
        LOG.debug("test_delete_portInUse - END")

    def test_update_port(self, tenant_id='test_tenant',
                         state=const.PORT_DOWN):
        """
        Tests updation of Ports.
        """

        LOG.debug("test_update_port - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            self.state)
        update_port_dict = self._l2network_plugin.update_port(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID], state=state)
        new_port = db.port_get(new_net_dict[const.NET_ID],
                               port_dict[const.PORT_ID])
        self.assertEqual(new_port[const.PORTSTATE], state)
        self.assertEqual(update_port_dict[const.PORT_STATE], state)
        self.tearDownNetworkPort(tenant_id, new_net_dict[const.NET_ID],
                                 port_dict[const.PORT_ID])
        LOG.debug("test_update_port - END")

    def test_update_port_networkDNE(self, tenant_id='test_tenant',
                                    net_id='0005', port_id='p0005'):
        """
        Tests updation of Ports when network does not exist.
        """

        LOG.debug("test_update_port_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_plugin.update_port, tenant_id,
                          net_id, port_id, state=const.PORT_UP)
        LOG.debug("test_update_port_networkDNE - END")

    def test_update_portDNE(self, tenant_id='test_tenant', port_id='p0005'):
        """
        Tests updation of Ports when port does not exist.
        """

        LOG.debug("test_update_portDNE - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        self.assertRaises(
            exc.PortNotFound, self._l2network_plugin.update_port, tenant_id,
            new_net_dict[const.NET_ID], port_id, state=const.PORT_UP)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_update_portDNE - END")

    def test_show_port(self, tenant_id='test_tenant'):
        """
        Tests display of Ports
        """

        LOG.debug("test_show_port - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            self.state)
        get_port_dict = self._l2network_plugin.get_port_details(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID])
        port = db.port_get(new_net_dict[const.NET_ID],
                           port_dict[const.PORT_ID])
        self.assertEqual(port[const.PORTSTATE], self.state)
        self.assertEqual(get_port_dict[const.PORT_STATE], self.state)
        self.tearDownNetworkPort(tenant_id, new_net_dict[const.NET_ID],
                                 port_dict[const.PORT_ID])
        LOG.debug("test_show_port - END")

    def test_show_port_networkDNE(self, tenant_id='test_tenant',
                                  net_id='0005', port_id='p0005'):
        """
        Tests display of Ports when network does not exist
        """

        LOG.debug("test_show_port_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_plugin.get_port_details,
                          tenant_id, net_id, port_id)
        LOG.debug("test_show_port_networkDNE - END")

    def test_show_portDNE(self, tenant_id='test_tenant', port_id='p0005'):
        """
        Tests display of Ports when port does not exist
        """

        LOG.debug("test_show_portDNE - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        self.assertRaises(exc.PortNotFound,
                          self._l2network_plugin.get_port_details, tenant_id,
                          new_net_dict[const.NET_ID], port_id)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_show_portDNE - END")

    def test_plug_interface(self,
                            tenant_id='test_tenant',
                            instance_tenant_id='nova',
                            nova_user_id='novaadmin',
                            instance_id=10,
                            vif_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc'):
        """
        Tests attachment of interface to the port
        """

        LOG.debug("test_plug_interface - START")
        new_net_dict = self._l2network_plugin.create_network(tenant_id,
                                                             self.network_name)
        port_dict = self._l2network_plugin.create_port(tenant_id,
                                                       new_net_dict[const.
                                                       NET_ID], self.state)
        instance_desc = {'project_id': tenant_id,
                         'user_id': nova_user_id}
        host_list = self._l2network_plugin.schedule_host(instance_tenant_id,
                                                         instance_id,
                                                         instance_desc)
        instance_vif_desc = {'project_id': tenant_id,
                             'user_id': nova_user_id,
                             'vif_id': vif_id}

        if conf.PLUGINS[const.PLUGINS].keys():
            vif_description = self._l2network_plugin.associate_port(
                instance_tenant_id, instance_id,
                instance_vif_desc)
        else:
            db.port_set_attachment_by_id(port_dict[const.PORT_ID],
                                         instance_vif_desc['vif_id'] +
                                         const.UNPLUGGED)

        self._l2network_plugin.plug_interface(tenant_id,
                                              new_net_dict[const.NET_ID],
                                              port_dict[const.PORT_ID], vif_id)
        port = db.port_get(new_net_dict[const.NET_ID],
                           port_dict[const.PORT_ID])
        self.assertEqual(port[const.INTERFACEID], vif_id)
        self.tearDownNetworkPortInterface(
            tenant_id, instance_tenant_id, instance_id, instance_vif_desc,
            new_net_dict[const.NET_ID], port_dict[const.PORT_ID])

        LOG.debug("test_plug_interface - END")

    def test_plug_interface_networkDNE(self,
                                       tenant_id='test_tenant',
                                       net_id='0005',
                                       port_id='p0005',
                                       remote_interface='new_interface'):
        """
        Tests attachment of interface network does not exist
        """

        LOG.debug("test_plug_interface_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_plugin.plug_interface, tenant_id,
                          net_id, port_id, remote_interface)
        LOG.debug("test_plug_interface_networkDNE - END")

    def test_plug_interface_portDNE(self, tenant_id='test_tenant',
                                    port_id='p0005',
                                    remote_interface='new_interface'):
        """
        Tests attachment of interface port does not exist
        """
        LOG.debug("test_plug_interface_portDNE - START")
        new_net_dict = self._l2network_plugin.create_network(tenant_id,
                                                             self.network_name)
        self.assertRaises(exc.PortNotFound,
                          self._l2network_plugin.plug_interface,
                          tenant_id, new_net_dict[const.NET_ID], port_id,
                          remote_interface)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_plug_interface_portDNE - END")

    def test_plug_interface_portInUse(self, tenant_id='test_tenant',
                                      instance_tenant_id='nova',
                                      nova_user_id='novaadmin',
                                      instance_id=10,
                                      vif_id='fe701ddf-26a2-42ea-'
                                             'b9e6-7313d1c522cc',
                                      remote_interface='new_interface'):
        """
        Tests attachment of new interface to the port when there is an
        existing attachment
        """
        LOG.debug("test_plug_interface_portInUse - START")
        new_net_dict = self._l2network_plugin.create_network(tenant_id,
                                                             self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID], self.state)
        instance_desc = {'project_id': tenant_id, 'user_id': nova_user_id}
        host_list = self._l2network_plugin.schedule_host(instance_tenant_id,
                                                         instance_id,
                                                         instance_desc)
        instance_vif_desc = {'project_id': tenant_id, 'user_id': nova_user_id,
                             'vif_id': vif_id}

        if conf.PLUGINS[const.PLUGINS].keys():
            vif_description = self._l2network_plugin.associate_port(
                instance_tenant_id, instance_id, instance_vif_desc)
        else:
            db.port_set_attachment_by_id(port_dict[const.PORT_ID],
                                         instance_vif_desc['vif_id'] +
                                         const.UNPLUGGED)

        self.assertRaises(exc.PortInUse, self._l2network_plugin.plug_interface,
                          tenant_id, new_net_dict[const.NET_ID],
                          port_dict[const.PORT_ID], remote_interface)
        self.tearDownNetworkPortInterface(tenant_id, instance_tenant_id,
                                          instance_id, instance_vif_desc,
                                          new_net_dict[const.NET_ID],
                                          port_dict[const.PORT_ID])

        LOG.debug("test_plug_interface_portInUse - END")

    def test_unplug_interface(self, tenant_id='test_tenant',
                              instance_tenant_id='nova',
                              nova_user_id='novaadmin', instance_id=10,
                              vif_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc'):
        """
        Tests detaachment of an interface to a port
        """
        LOG.debug("test_unplug_interface - START")
        new_net_dict = self._l2network_plugin.create_network(tenant_id,
                                                             self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID], self.state)
        instance_desc = {'project_id': tenant_id,
                         'user_id': nova_user_id}
        host_list = self._l2network_plugin.schedule_host(instance_tenant_id,
                                                         instance_id,
                                                         instance_desc)
        instance_vif_desc = {'project_id': tenant_id, 'user_id': nova_user_id,
                             'vif_id': vif_id}

        if conf.PLUGINS[const.PLUGINS].keys():
            vif_description = self._l2network_plugin. associate_port(
                instance_tenant_id,
                instance_id,
                instance_vif_desc)
        else:
            db.port_set_attachment_by_id(port_dict[const.PORT_ID],
                                         instance_vif_desc['vif_id'] +
                                         const.UNPLUGGED)

        self._l2network_plugin.plug_interface(tenant_id,
                                              new_net_dict[const.NET_ID],
                                              port_dict[const.PORT_ID], vif_id)
        self._l2network_plugin.unplug_interface(tenant_id,
                                                new_net_dict[const.NET_ID],
                                                port_dict[const.PORT_ID])
        port = db.port_get(new_net_dict[const.NET_ID],
                           port_dict[const.PORT_ID])
        vif_id_unplugged = vif_id + '(detached)'
        self.assertEqual(port[const.INTERFACEID], vif_id_unplugged)
        self.tearDownNetworkPortInterface(tenant_id, instance_tenant_id,
                                          instance_id, instance_vif_desc,
                                          new_net_dict[const.NET_ID],
                                          port_dict[const.PORT_ID])

        LOG.debug("test_unplug_interface - END")

    def test_unplug_interface_networkDNE(self, tenant_id='test_tenant',
                                         net_id='0005', port_id='p0005'):
        """
        Tests detaachment of an interface to a port, when the network does
        not exist
        """

        LOG.debug("test_unplug_interface_networkDNE - START")
        self.assertRaises(exc.NetworkNotFound,
                          self._l2network_plugin.unplug_interface,
                          tenant_id, net_id, port_id)
        LOG.debug("test_unplug_interface_networkDNE - END")

    def test_unplug_interface_portDNE(self, tenant_id='test_tenant',
                                      port_id='p0005'):
        """
        Tests detaachment of an interface to a port, when the port does
        not exist
        """

        LOG.debug("test_unplug_interface_portDNE - START")
        new_net_dict = self._l2network_plugin.create_network(tenant_id,
                                                             self.network_name)
        self.assertRaises(exc.PortNotFound,
                          self._l2network_plugin.unplug_interface, tenant_id,
                          new_net_dict[const.NET_ID], port_id)
        self.tearDownNetwork(tenant_id, new_net_dict[const.NET_ID])
        LOG.debug("test_unplug_interface_portDNE - END")

    def test_create_portprofile(self, net_tenant_id=None,
                                net_profile_name=None, net_qos=None):
        """
        Tests creation of a port-profile
        """

        LOG.debug("test_create_portprofile - tenant id: %s - START",
                  net_tenant_id)
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        if net_profile_name:
            profile_name = net_profile_name
        else:
            profile_name = self.profile_name
        if net_qos:
            qos = net_qos
        else:
            qos = self.qos
        port_profile_dict = self._l2network_plugin.create_portprofile(
            tenant_id, profile_name, qos)
        port_profile_id = port_profile_dict['profile_id']
        port_profile = cdb.get_portprofile(tenant_id, port_profile_id)
        self.assertEqual(port_profile[const.PPNAME], profile_name)
        self.assertEqual(port_profile[const.PPQOS], qos)
        self.tearDownPortProfile(tenant_id, port_profile_id)
        LOG.debug("test_create_portprofile - tenant id: %s - END",
                  net_tenant_id)

    def test_delete_portprofile(self, net_tenant_id=None):
        """
        Tests deletion of a port-profile
        """

        LOG.debug("test_delete_portprofile - tenant id: %s - START",
                  net_tenant_id)
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        port_profile_dict = self._l2network_plugin.create_portprofile(
            tenant_id, self.profile_name, self.qos)
        port_profile_id = port_profile_dict['profile_id']
        self._l2network_plugin.delete_portprofile(tenant_id, port_profile_id)
        self.assertRaises(Exception, cdb.get_portprofile, port_profile_id)
        LOG.debug("test_delete_portprofile - tenant id: %s - END",
                  net_tenant_id)

    def test_delete_portprofileDNE(self, tenant_id='test_tenant',
                                   profile_id='pr0005'):
        """
        Tests deletion of a port-profile when netowrk does not exist
        """

        LOG.debug("test_delete_portprofileDNE - START")
        self.assertRaises(cexc.PortProfileNotFound,
                          self._l2network_plugin.delete_portprofile,
                          tenant_id, profile_id)
        LOG.debug("test_delete_portprofileDNE - END")

    def test_delete_portprofileAssociated(self, tenant_id='test_tenant'):

        """
        Tests deletion of an associatedport-profile
        """

        LOG.debug("test_delete_portprofileAssociated - START")
        port_profile_dict = self._l2network_plugin.create_portprofile(
            tenant_id, self.profile_name, self.qos)
        port_profile_id = port_profile_dict['profile_id']
        new_net_dict = self._l2network_plugin.create_network(tenant_id,
                                                             'test_network')
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            const.PORT_UP)
        self._l2network_plugin.associate_portprofile(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID], port_profile_id)
        self.assertRaises(cexc.PortProfileInvalidDelete,
                          self._l2network_plugin.delete_portprofile,
                          tenant_id, port_profile_id)
        self.tearDownAssociatePortProfile(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID], port_profile_id)
        self.tearDownNetworkPort(tenant_id, new_net_dict[const.NET_ID],
                                 port_dict[const.PORT_ID])
        LOG.debug("test_delete_portprofileAssociated - END")

    def test_list_portprofile(self, tenant_id='test_tenant'):
        """
        Tests listing of port-profiles
        """

        LOG.debug("test_list_portprofile - tenant id: %s - START", tenant_id)
        profile_name2 = tenant_id + '_port_profile2'
        qos2 = tenant_id + 'qos2'
        port_profile_dict1 = self._l2network_plugin.create_portprofile(
            tenant_id, self.profile_name, self.qos)
        port_profile_dict2 = self._l2network_plugin.create_portprofile(
            tenant_id, profile_name2, qos2)
        port_profile_id1 = port_profile_dict1['profile_id']
        port_profile_id2 = port_profile_dict2['profile_id']
        list_all_portprofiles = self._l2network_plugin.get_all_portprofiles(
            tenant_id)
        port_profile_list = [port_profile_dict1, port_profile_dict2]
        pplist = cdb.get_all_portprofiles()
        new_pplist = []
        for pp in pplist:
            new_pp = self._make_portprofile_dict(tenant_id,
                                                 pp[const.UUID],
                                                 pp[const.PPNAME],
                                                 pp[const.PPQOS])
            new_pplist.append(new_pp)
        self.assertTrue(new_pplist[0] in port_profile_list)
        self.assertTrue(new_pplist[1] in port_profile_list)
        self.tearDownPortProfile(tenant_id, port_profile_id1)
        self.tearDownPortProfile(tenant_id, port_profile_id2)

        LOG.debug("test_list_portprofile - tenant id: %s - END", tenant_id)

    def test_show_portprofile(self, net_tenant_id=None):
        """
        Tests display of a port-profile
        """

        LOG.debug("test_show_portprofile - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        port_profile_dict = self._l2network_plugin.create_portprofile(
            tenant_id, self.profile_name, self.qos)
        port_profile_id = port_profile_dict['profile_id']
        result_port_profile = self._l2network_plugin.get_portprofile_details(
            tenant_id, port_profile_id)
        port_profile = cdb.get_portprofile(tenant_id, port_profile_id)
        self.assertEqual(port_profile[const.PPQOS], self.qos)
        self.assertEqual(port_profile[const.PPNAME], self.profile_name)
        self.assertEqual(result_port_profile[const.PROFILE_QOS],
                         self.qos)
        self.assertEqual(result_port_profile[const.PROFILE_NAME],
                         self.profile_name)
        self.tearDownPortProfile(tenant_id, port_profile_id)
        LOG.debug("test_show_portprofile - tenant id: %s - END", net_tenant_id)

    def test_show_portprofileDNE(self, tenant_id='test_tenant',
                                 profile_id='pr0005'):
        """
        Tests display of a port-profile when network does not exist
        """

        LOG.debug("test_show_portprofileDNE - START")
        self.assertRaises(Exception,
                          self._l2network_plugin.get_portprofile_details,
                          tenant_id, profile_id)
        LOG.debug("test_show_portprofileDNE - END")

    def test_rename_portprofile(self, tenant_id='test_tenant',
                                new_profile_name='new_profile_name'):
        """
        Tests rename of a port-profile
        """

        LOG.debug("test_rename_portprofile - START")
        port_profile_dict = self._l2network_plugin.create_portprofile(
            tenant_id, self.profile_name, self.qos)
        port_profile_id = port_profile_dict['profile_id']
        result_port_profile_dict = self._l2network_plugin.rename_portprofile(
            tenant_id, port_profile_id, new_profile_name)
        port_profile = cdb.get_portprofile(tenant_id, port_profile_id)
        self.assertEqual(port_profile[const.PPNAME], new_profile_name)
        self.assertEqual(result_port_profile_dict[const.PROFILE_NAME],
                         new_profile_name)
        self.tearDownPortProfile(tenant_id, port_profile_id)
        LOG.debug("test_show_portprofile - tenant id: %s - END")

    def test_rename_portprofileDNE(self, tenant_id='test_tenant',
                                   profile_id='pr0005',
                                   new_profile_name='new_profile_name'):
        """
        Tests rename of a port-profile when network does not exist
        """

        LOG.debug("test_rename_portprofileDNE - START")
        self.assertRaises(cexc.PortProfileNotFound,
                          self._l2network_plugin.rename_portprofile,
                          tenant_id, profile_id, new_profile_name)
        LOG.debug("test_rename_portprofileDNE - END")

    def test_associate_portprofile(self, tenant_id='test_tenant'):
        """
        Tests association of a port-profile
        """

        LOG.debug("test_associate_portprofile - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            self.state)
        port_profile_dict = self._l2network_plugin.create_portprofile(
            tenant_id, self.profile_name, self.qos)
        port_profile_id = port_profile_dict['profile_id']
        self._l2network_plugin.associate_portprofile(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID], port_profile_id)
        port_profile_associate = cdb.get_pp_binding(tenant_id, port_profile_id)
        self.assertEqual(port_profile_associate[const.PORTID],
                         port_dict[const.PORT_ID])
        self.tearDownAssociatePortProfile(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID], port_profile_id)
        self.tearDownNetworkPort(tenant_id, new_net_dict[const.NET_ID],
                                 port_dict[const.PORT_ID])
        LOG.debug("test_associate_portprofile - END")

    def test_associate_portprofileDNE(self, tenant_id='test_tenant',
                                      net_id='0005', port_id='p00005',
                                      profile_id='pr0005'):
        """
        Tests association of a port-profile when a network does not exist
        """

        LOG.debug("test_associate_portprofileDNE - START")
        self.assertRaises(cexc.PortProfileNotFound,
                          self._l2network_plugin.associate_portprofile,
                          tenant_id, net_id, port_id, profile_id)
        LOG.debug("test_associate_portprofileDNE - END")

    def test_disassociate_portprofile(self, tenant_id='test_tenant',
                                      ):
        """
        Tests disassociation of a port-profile
        """

        LOG.debug("test_disassociate_portprofile - START")
        new_net_dict = self._l2network_plugin.create_network(
            tenant_id, self.network_name)
        port_dict = self._l2network_plugin.create_port(
            tenant_id, new_net_dict[const.NET_ID],
            self.state)
        port_profile_dict = self._l2network_plugin.create_portprofile(
            tenant_id, self.profile_name, self.qos)
        port_profile_id = port_profile_dict['profile_id']
        self._l2network_plugin.associate_portprofile(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID], port_profile_id)
        self._l2network_plugin.disassociate_portprofile(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID], port_profile_id)
        port_profile_associate = cdb.get_pp_binding(tenant_id, port_profile_id)
        self.assertEqual(port_profile_associate, [])
        self.tearDownPortProfile(tenant_id, port_profile_id)
        self.tearDownNetworkPort(
            tenant_id, new_net_dict[const.NET_ID],
            port_dict[const.PORT_ID])
        LOG.debug("test_disassociate_portprofile - END")

    def test_disassociate_portprofileDNE(self, tenant_id='test_tenant',
                                         net_id='0005', port_id='p00005',
                                         profile_id='pr0005'):
        """
        Tests disassociation of a port-profile when network does not exist
        """

        LOG.debug("test_disassociate_portprofileDNE - START")
        self.assertRaises(cexc.PortProfileNotFound,
                          self._l2network_plugin.disassociate_portprofile,
                          tenant_id, net_id, port_id, profile_id)
        LOG.debug("test_disassociate_portprofileDNE - END")

    def test_get_vlan_name(self, net_tenant_id=None, vlan_id="NewVlan",
                           vlan_prefix=conf.VLAN_NAME_PREFIX):
        """
        Tests get vlan name
        """

        LOG.debug("test_get_vlan_name  - START")
        if net_tenant_id:
            tenant_id = net_tenant_id
        else:
            tenant_id = self.tenant_id
        result_vlan_name = self._l2network_plugin._get_vlan_name(tenant_id,
                                                                 vlan_id)
        expected_output = vlan_prefix + vlan_id
        self.assertEqual(result_vlan_name, expected_output)
        LOG.debug("test_get_vlan_name - END")

    def test_validate_port_state(self, state=const.PORT_UP):
        """
        Tests validate port state
        """

        LOG.debug("test_validate_port_state - START")
        result = self._l2network_plugin._validate_port_state(state)
        self.assertEqual(result, True)
        LOG.debug("test_validate_port_state - END")

    def test_invalid_port_state(self, state="BADSTATE"):
        """
        Tests invalidate port state
        """

        LOG.debug("test_validate_port_state - START")
        self.assertRaises(exc.StateInvalid,
                          self._l2network_plugin._validate_port_state,
                          state)
        LOG.debug("test_validate_port_state - END")

    def setUp(self):
        """
        Set up function
        """
        self.tenant_id = "test_tenant"
        self.network_name = "test_network"
        self.profile_name = "test_tenant_port_profile"
        self.qos = "test_qos"
        self.state = const.PORT_UP
        self.net_id = '00005'
        self.port_id = 'p0005'
        self.remote_interface = 'new_interface'
        self._l2network_plugin = l2network_plugin.L2Network()

    """
        Clean up functions after the tests
    """
    def tearDown(self):
        """Clear the test environment"""
        # Remove database contents
        db.clear_db()

    def tearDownNetwork(self, tenant_id, network_dict_id):
        """
        Tear down the Network
        """
        self._l2network_plugin.delete_network(tenant_id, network_dict_id)

    def tearDownPortOnly(self, tenant_id, network_dict_id, port_id):
        """
        Tear doen the port
        """
        self._l2network_plugin.delete_port(tenant_id, network_dict_id, port_id)

    def tearDownNetworkPort(self, tenant_id, network_dict_id, port_id):
        """
        Tear down Network Port
        """
        self._l2network_plugin.delete_port(tenant_id, network_dict_id, port_id)
        self.tearDownNetwork(tenant_id, network_dict_id)

    def tearDownNetworkPortInterface(self, tenant_id, instance_tenant_id,
                                     instance_id, instance_desc,
                                     network_dict_id, port_id):
        """
        Tear down Network Port Interface
        """
        if not conf.PLUGINS[const.PLUGINS].keys():
            db.port_unset_attachment_by_id(port_id)
        else:
            self._l2network_plugin.detach_port(instance_tenant_id, instance_id,
                                               instance_desc)
        self.tearDownNetworkPort(tenant_id, network_dict_id, port_id)

    def tearDownPortProfile(self, tenant_id, port_profile_id):
        """
        Tear down Port Profile
        """
        self._l2network_plugin.delete_portprofile(tenant_id, port_profile_id)

    def tearDownPortProfileBinding(self, tenant_id, port_profile_id):
        """
        Tear down port profile binding
        """
        self._l2network_plugin.delete_portprofile(tenant_id, port_profile_id)

    def tearDownAssociatePortProfile(self, tenant_id, net_id, port_id,
                                     port_profile_id):
        """
        Tear down associate port profile
        """
        self._l2network_plugin.disassociate_portprofile(
            tenant_id, net_id, port_id, port_profile_id)
        self.tearDownPortProfile(tenant_id, port_profile_id)

    def _make_net_dict(self, net_id, net_name, ports):
        res = {const.NET_ID: net_id, const.NET_NAME: net_name}
        res[const.NET_PORTS] = ports
        return res

    def _make_port_dict(self, port_id, state, net_id, attachment):
        res = {const.PORT_ID: port_id, const.PORT_STATE: state}
        res[const.NET_ID] = net_id
        res[const.ATTACHMENT] = attachment
        return res

    def _make_portprofile_dict(self, tenant_id, profile_id, profile_name,
                               qos):
        profile_associations = self._make_portprofile_assc_list(
            tenant_id, profile_id)
        res = {
            const.PROFILE_ID: str(profile_id),
            const.PROFILE_NAME: profile_name,
            const.PROFILE_ASSOCIATIONS: profile_associations,
            const.PROFILE_VLAN_ID: None,
            const.PROFILE_QOS: qos,
        }
        return res

    def _make_portprofile_assc_list(self, tenant_id, profile_id):
        plist = cdb.get_pp_binding(tenant_id, profile_id)
        assc_list = []
        for port in plist:
            assc_list.append(port[const.PORTID])

        return assc_list
