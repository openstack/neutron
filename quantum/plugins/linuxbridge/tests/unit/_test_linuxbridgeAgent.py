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
# @author: Shweta Padubidri, Cisco Systems, Inc.

import ConfigParser
import logging
import os
import shlex
import signal
import subprocess
import sys
import unittest

import quantum.db.api as db
from quantum.plugins.linuxbridge import LinuxBridgePlugin
from quantum.plugins.linuxbridge.agent import (
    linuxbridge_quantum_agent as linux_agent,
    )
from quantum.plugins.linuxbridge.common import constants as lconst
from quantum.plugins.linuxbridge.db import l2network_db as cdb


LOG = logging.getLogger(__name__)


class LinuxBridgeAgentTest(unittest.TestCase):

    def test_add_gateway_interface(
        self, tenant_id="test_tenant", network_name="test_network",
        interface_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc',
        mac_address='fe:16:3e:51:60:dd'):

        LOG.debug("test_tap_gateway_interface - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.plug_interface(
            tenant_id, new_network[lconst.NET_ID],
            new_port[lconst.PORT_ID], interface_id)
        bridge_name = self.br_name_prefix + new_network[lconst.NET_ID][0:11]
        self.create_bridge(bridge_name)
        device_name = self.gw_name_prefix + new_network[lconst.NET_ID][0:11]
        self.create_device(device_name, mac_address)

        vlan_bind = cdb.get_vlan_binding(new_network[lconst.NET_ID])
        vlan_id = vlan_bind[lconst.VLANID]

        self._linuxbridge_quantum_agent.process_port_binding(
            new_port[lconst.PORT_ID], new_network[lconst.NET_ID],
            device_name, str(vlan_id))
        list_interface = (self._linuxbridge_quantum_agent.linux_br.
                          get_interfaces_on_bridge(bridge_name))

        self.assertTrue(device_name in list_interface)
        for interface in list_interface:
            self._linuxbridge_quantum_agent.linux_br.remove_interface(
                bridge_name, interface)
            self.delete_device(interface)
        self.delete_bridge(bridge_name)
        self.tearDownUnplugInterface(tenant_id, new_network[lconst.NET_ID],
                                     new_port[lconst.PORT_ID])

        LOG.debug("test_add_gateway_interface - END")

    def test_add_tap_interface(
        self, tenant_id="test_tenant", network_name="test_network",
        interface_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc',
        mac_address='fe:16:3e:51:60:dd'):

        LOG.debug("test_add_tap_interface - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.plug_interface(
            tenant_id, new_network[lconst.NET_ID],
            new_port[lconst.PORT_ID], interface_id)
        bridge_name = self.br_name_prefix + new_network[lconst.NET_ID][0:11]
        self.create_bridge(bridge_name)
        device_name = self.tap_name_prefix + interface_id[0:11]
        self.create_device(device_name, mac_address)

        vlan_bind = cdb.get_vlan_binding(new_network[lconst.NET_ID])
        vlan_id = vlan_bind[lconst.VLANID]

        self._linuxbridge_quantum_agent.process_port_binding(
            new_port[lconst.PORT_ID], new_network[lconst.NET_ID],
            interface_id, str(vlan_id))
        list_interface = (self._linuxbridge_quantum_agent.linux_br.
                          get_interfaces_on_bridge(bridge_name))

        self.assertTrue(device_name in list_interface)
        for interface in list_interface:
            self._linuxbridge_quantum_agent.linux_br.remove_interface(
                bridge_name, interface)
            self.delete_device(interface)
        self.delete_bridge(bridge_name)
        self.tearDownUnplugInterface(tenant_id, new_network[lconst.NET_ID],
                                     new_port[lconst.PORT_ID])

        LOG.debug("test_add_tap_interface -END")

    def test_remove_interface(
                  self, tenant_id="test_tenant", network_name="test_network",
                  interface_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc',
                  mac_address='fe:16:3e:51:60:dd'):

        LOG.debug("test_remove_interface - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.plug_interface(
            tenant_id, new_network[lconst.NET_ID],
            new_port[lconst.PORT_ID], interface_id)
        bridge_name = self.br_name_prefix + new_network[lconst.NET_ID][0:11]
        self.create_bridge(bridge_name)
        device_name = self.tap_name_prefix + interface_id[0:11]
        self.create_device(device_name, mac_address)

        vlan_bind = cdb.get_vlan_binding(new_network[lconst.NET_ID])
        vlan_id = vlan_bind[lconst.VLANID]

        self._linuxbridge_quantum_agent.process_port_binding(
            new_port[lconst.PORT_ID], new_network[lconst.NET_ID],
            interface_id, str(vlan_id))
        list_interface = (self._linuxbridge_quantum_agent.linux_br.
                          get_interfaces_on_bridge(bridge_name))

        self._linuxbridge_quantum_agent.linux_br.remove_interface(bridge_name,
                                                                  device_name)
        list_interface = (self._linuxbridge_quantum_agent.linux_br.
                          get_interfaces_on_bridge(bridge_name))
        self.assertFalse(device_name in list_interface)
        for interface in list_interface:
            self._linuxbridge_quantum_agent.linux_br.remove_interface(
                bridge_name, interface)
            self.delete_device(interface)
        self.delete_device(device_name)
        self.delete_bridge(bridge_name)
        self.tearDownUnplugInterface(tenant_id, new_network[lconst.NET_ID],
                                     new_port[lconst.PORT_ID])

        LOG.debug("test_remove_interface -END")

    def test_ensure_vlan_bridge(
        self, tenant_id="test_tenant",
        network_name="test_network",
        interface_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc'):

        LOG.debug("test_ensure_vlan_bridge - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.plug_interface(
            tenant_id, new_network[lconst.NET_ID],
            new_port[lconst.PORT_ID], interface_id)
        bridge_name = self.br_name_prefix + new_network[lconst.NET_ID][0:11]
        vlan_bind = cdb.get_vlan_binding(new_network[lconst.NET_ID])
        vlan_id = vlan_bind[lconst.VLANID]
        vlan_subinterface = self.physical_interface + '.' + str(vlan_id)

        self._linuxbridge_quantum_agent.linux_br.ensure_vlan_bridge(
            new_network[lconst.NET_ID], str(vlan_id))
        list_quantum_bridges = (self._linuxbridge_quantum_agent.linux_br.
                               get_all_quantum_bridges())
        self.assertTrue(bridge_name in list_quantum_bridges)
        list_interface = (self._linuxbridge_quantum_agent.linux_br.
                          get_interfaces_on_bridge(bridge_name))
        self.assertTrue(vlan_subinterface in list_interface)

        for interface in list_interface:
            self._linuxbridge_quantum_agent.linux_br.remove_interface(
                bridge_name, interface)
            self.delete_device(interface)
        self.delete_bridge(bridge_name)
        self.tearDownUnplugInterface(tenant_id, new_network[lconst.NET_ID],
                                     new_port[lconst.PORT_ID])

        LOG.debug("test_ensure_vlan_bridge -END")

    def test_delete_vlan_bridge(
        self, tenant_id="test_tenant", network_name="test_network",
        interface_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc'):

        LOG.debug("test_delete_vlan_bridge - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.plug_interface(
            tenant_id, new_network[lconst.NET_ID],
            new_port[lconst.PORT_ID], interface_id)
        bridge_name = self.br_name_prefix + new_network[lconst.NET_ID][0:11]
        vlan_bind = cdb.get_vlan_binding(new_network[lconst.NET_ID])
        vlan_id = vlan_bind[lconst.VLANID]
        vlan_subinterface = self.physical_interface + '.' + str(vlan_id)

        self._linuxbridge_quantum_agent.linux_br.ensure_vlan_bridge(
            new_network[lconst.NET_ID], str(vlan_id))
        self._linuxbridge_quantum_agent.linux_br.delete_vlan_bridge(
            bridge_name)

        self.assertEquals(self.device_exists(vlan_subinterface), False)
        self.assertEquals(self.device_exists(bridge_name), False)
        self.tearDownUnplugInterface(tenant_id, new_network[lconst.NET_ID],
                                     new_port[lconst.PORT_ID])

        LOG.debug("test_delete_vlan_bridge - END")

    def test_process_deleted_networks(
        self, tenant_id="test_tenant", network_name="test_network",
        interface_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc'):

        LOG.debug("test_delete_vlan_bridge - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.plug_interface(
            tenant_id, new_network[lconst.NET_ID],
            new_port[lconst.PORT_ID], interface_id)
        bridge_name = self.br_name_prefix + new_network[lconst.NET_ID][0:11]
        vlan_bindings = {}
        vlan_bindings[new_network[lconst.NET_ID]] = (
            cdb.get_vlan_binding(new_network[lconst.NET_ID]))
        vlan_id = vlan_bindings[new_network[lconst.NET_ID]][lconst.VLANID]
        vlan_subinterface = self.physical_interface + '.' + str(vlan_id)

        self._linuxbridge_quantum_agent.linux_br.ensure_vlan_bridge(
            new_network[lconst.NET_ID], str(vlan_id))
        self.tearDownUnplugInterface(tenant_id, new_network[lconst.NET_ID],
                                     new_port[lconst.PORT_ID])
        vlan_bindings = {}
        self._linuxbridge_quantum_agent.process_deleted_networks(vlan_bindings)

        self.assertEquals(self.device_exists(vlan_subinterface), False)
        self.assertEquals(self.device_exists(bridge_name), False)
        LOG.debug("test_delete_vlan_bridge - END")

    def test_process_unplugged_tap_interface(
        self, tenant_id="test_tenant", network_name="test_network",
        interface_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc',
        mac_address='fe:16:3e:51:60:dd'):

        LOG.debug("test_process_unplugged_tap_interface - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.plug_interface(
            tenant_id, new_network[lconst.NET_ID],
            new_port[lconst.PORT_ID], interface_id)
        bridge_name = self.br_name_prefix + new_network[lconst.NET_ID][0:11]
        self.create_bridge(bridge_name)
        device_name = self.tap_name_prefix + interface_id[0:11]
        self.create_device(device_name, mac_address)

        vlan_bind = cdb.get_vlan_binding(new_network[lconst.NET_ID])
        vlan_id = vlan_bind[lconst.VLANID]

        self._linuxbridge_quantum_agent.process_port_binding(
            new_port[lconst.PORT_ID], new_network[lconst.NET_ID],
            interface_id, str(vlan_id))
        list_interface = self._linuxbridge_quantum_agent.linux_br.\
                         get_interfaces_on_bridge(bridge_name)
        self._linuxbridge_plugin.unplug_interface(tenant_id,
                                                  new_network[lconst.NET_ID],
                                                  new_port[lconst.PORT_ID])
        plugged_interface = []
        self._linuxbridge_quantum_agent.process_unplugged_interfaces(
            plugged_interface)
        list_interface = (self._linuxbridge_quantum_agent.linux_br.
                         get_interfaces_on_bridge(bridge_name))
        self.assertFalse(device_name in list_interface)
        for interface in list_interface:
            self._linuxbridge_quantum_agent.linux_br.remove_interface(
                bridge_name, interface)
            self.delete_device(interface)
        self.delete_device(device_name)
        self.delete_bridge(bridge_name)
        self.tearDownNetworkPort(tenant_id, new_network[lconst.NET_ID],
                                 new_port[lconst.PORT_ID])

        LOG.debug("test_test_process_unplugged_tap_interface -END")

    def test_process_unplugged_interface_empty(
        self, tenant_id="test_tenant", network_name="test_network"):
        """ test to unplug not plugged port. It should not raise exception
        """
        LOG.debug("test_process_unplugged_interface_empty - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.unplug_interface(tenant_id,
                                                  new_network[lconst.NET_ID],
                                                  new_port[lconst.PORT_ID])
        self.tearDownNetworkPort(tenant_id, new_network[lconst.NET_ID],
                                 new_port[lconst.PORT_ID])

        LOG.debug("test_process_unplugged_interface_empty -END")

    def test_process_unplugged_gw_interface(
        self, tenant_id="test_tenant", network_name="test_network",
        interface_id='fe701ddf-26a2-42ea-b9e6-7313d1c522cc',
        mac_address='fe:16:3e:51:60:dd'):

        LOG.debug("test_process_unplugged_gw_interface - START")
        new_network = (
            self._linuxbridge_plugin.create_network(tenant_id, network_name))
        new_port = self._linuxbridge_plugin.create_port(
            tenant_id, new_network[lconst.NET_ID], lconst.PORT_UP)
        self._linuxbridge_plugin.plug_interface(
            tenant_id, new_network[lconst.NET_ID],
            new_port[lconst.PORT_ID], interface_id)
        bridge_name = self.br_name_prefix + new_network[lconst.NET_ID][0:11]
        self.create_bridge(bridge_name)
        device_name = self.gw_name_prefix + new_network[lconst.NET_ID][0:11]
        self.create_device(device_name, mac_address)

        vlan_bind = cdb.get_vlan_binding(new_network[lconst.NET_ID])
        vlan_id = vlan_bind[lconst.VLANID]

        self._linuxbridge_quantum_agent.process_port_binding(
            new_port[lconst.PORT_ID], new_network[lconst.NET_ID],
            interface_id, str(vlan_id))
        list_interface = (self._linuxbridge_quantum_agent.linux_br.
                          get_interfaces_on_bridge(bridge_name))
        self._linuxbridge_plugin.unplug_interface(tenant_id,
                                                  new_network[lconst.NET_ID],
                                                  new_port[lconst.PORT_ID])
        plugged_interface = []
        self._linuxbridge_quantum_agent.process_unplugged_interfaces(
            plugged_interface)
        list_interface = (self._linuxbridge_quantum_agent.linux_br.
                         get_interfaces_on_bridge(bridge_name))
        self.assertFalse(device_name in list_interface)
        for interface in list_interface:
            self._linuxbridge_quantum_agent.linux_br.remove_interface(
                bridge_name, interface)
            self.delete_device(interface)
        self.delete_device(device_name)
        self.delete_bridge(bridge_name)
        self.tearDownNetworkPort(tenant_id, new_network[lconst.NET_ID],
                                 new_port[lconst.PORT_ID])

        LOG.debug("test_test_process_unplugged_gw_interface -END")

    def create_bridge(self, bridge_name):
        """
        Create a bridge
        """
        self.run_cmd(['brctl', 'addbr', bridge_name])
        self.run_cmd(['brctl', 'setfd', bridge_name, str(0)])
        self.run_cmd(['brctl', 'stp', bridge_name, 'off'])
        self.run_cmd(['ip', 'link', 'set', bridge_name, 'up'])

    def delete_bridge(self, bridge_name):
        """
        Delete a bridge
        """
        self.run_cmd(['ip', 'link', 'set', bridge_name, 'down'])
        self.run_cmd(['brctl', 'delbr', bridge_name])

    def create_device(self, dev, mac_address):
        self.run_cmd(['ip', 'tuntap', 'add', dev, 'mode', 'tap'])
        self.run_cmd(['ip', 'link', 'set', dev, "address", mac_address])
        self.run_cmd(['ip', 'link', 'set', dev, 'up'])

    def delete_device(self, dev):
        self.run_cmd(['ip', 'link', 'delete', dev])

    def setUp(self):
        """
        Set up function
        """
        self.tenant_id = "test_tenant"
        self.network_name = "test_network"
        self.config_file = os.path.join(os.path.dirname(__file__), os.pardir,
                                        os.pardir, os.pardir, os.pardir,
                                        os.pardir, "etc", "quantum",
                                        "plugins", "linuxbridge",
                                        "linuxbridge_conf.ini")

        config = ConfigParser.ConfigParser()
        self.br_name_prefix = "brq"
        self.gw_name_prefix = "gw-"
        self.tap_name_prefix = "tap"
        self._linuxbridge_plugin = LinuxBridgePlugin.LinuxBridgePlugin()
        try:
            fh = open(self.config_file)
            fh.close()
            config.read(self.config_file)
            self.physical_interface = config.get("LINUX_BRIDGE",
                                                 "physical_interface")
            self.polling_interval = config.get("AGENT", "polling_interval")
            self.reconnect_interval = config.get("DATABASE",
                                                 "reconnect_interval")
            self.root_helper = config.get("AGENT", "root_helper")
        except Exception, e:
            LOG.error("Unable to parse config file \"%s\": \nException%s"
                      % (self.config_file, str(e)))
            sys.exit(1)
        self._linuxbridge = linux_agent.LinuxBridge(self.br_name_prefix,
                                                    self.physical_interface,
                                                    self.root_helper)
        self._linuxbridge_quantum_agent = linux_agent.LinuxBridgeQuantumAgent(
            self.br_name_prefix,
            self.physical_interface,
            self.polling_interval,
            self.reconnect_interval,
            self.root_helper)

    def run_cmd(self, args):
        cmd = shlex.split(self.root_helper) + args
        LOG.debug("Running command: " + " ".join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        retval = p.communicate()[0]
        if p.returncode == -(signal.SIGALRM):
            LOG.debug("Timeout running command: " + " ".join(args))
        if retval:
            LOG.debug("Command returned: %s" % retval)
        return retval

    def device_exists(self, device):
        """Check if ethernet device exists."""
        retval = self.run_cmd(['ip', 'link', 'show', 'dev', device])
        if retval:
            return True
        else:
            return False

    """
         Clean up functions after the tests
    """
    def tearDown(self):
        """Clear the test environment(Clean the Database)"""
        db.clear_db()

    def tearDownNetwork(self, tenant_id, network_dict_id):
        """
        Tear down the Network
        """
        self._linuxbridge_plugin.delete_network(tenant_id, network_dict_id)

    def tearDownUnplugInterface(self, tenant_id, network_dict_id, port_id):
        """
        Tear down the port
        """
        self._linuxbridge_plugin.unplug_interface(tenant_id, network_dict_id,
                                                  port_id)
        self.tearDownNetworkPort(tenant_id, network_dict_id, port_id)

    def tearDownNetworkPort(self, tenant_id, network_dict_id, port_id):
        """
        Tear down Network Port
        """
        self._linuxbridge_plugin.delete_port(tenant_id, network_dict_id,
                                             port_id)
        self.tearDownNetwork(tenant_id, network_dict_id)
