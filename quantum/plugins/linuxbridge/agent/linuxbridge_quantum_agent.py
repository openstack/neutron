#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.
# All Rights Reserved.
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
#
# Performs per host Linux Bridge configuration for Quantum.
# Based on the structure of the OpenVSwitch agent in the
# Quantum OpenVSwitch Plugin.
# @author: Sumit Naiksatam, Cisco Systems, Inc.

import logging
import os
import shlex
import signal
import subprocess
import sys
import time

import eventlet
import pyudev
from sqlalchemy.ext.sqlsoup import SqlSoup

from quantum.agent import rpc as agent_rpc
from quantum.common import config as logging_config
from quantum.common import topics
from quantum.openstack.common import cfg
from quantum.openstack.common import context
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.plugins.linuxbridge.common import config

from quantum.agent.linux import utils

logging.basicConfig()
LOG = logging.getLogger(__name__)

BRIDGE_NAME_PREFIX = "brq"
GATEWAY_INTERFACE_PREFIX = "gw-"
TAP_INTERFACE_PREFIX = "tap"
BRIDGE_FS = "/sys/devices/virtual/net/"
BRIDGE_NAME_PLACEHOLDER = "bridge_name"
BRIDGE_INTERFACES_FS = BRIDGE_FS + BRIDGE_NAME_PLACEHOLDER + "/brif/"
PORT_OPSTATUS_UPDATESQL = "UPDATE ports SET op_status = '%s' WHERE uuid = '%s'"
DEVICE_NAME_PLACEHOLDER = "device_name"
BRIDGE_PORT_FS_FOR_DEVICE = BRIDGE_FS + DEVICE_NAME_PLACEHOLDER + "/brport"
VLAN_BINDINGS = "vlan_bindings"
PORT_BINDINGS = "port_bindings"
OP_STATUS_UP = "UP"
OP_STATUS_DOWN = "DOWN"
# Default inteval values
DEFAULT_POLLING_INTERVAL = 2
DEFAULT_RECONNECT_INTERVAL = 2


class LinuxBridge:
    def __init__(self, br_name_prefix, physical_interface, root_helper):
        self.br_name_prefix = br_name_prefix
        self.physical_interface = physical_interface
        self.root_helper = root_helper

    def device_exists(self, device):
        """Check if ethernet device exists."""
        try:
            utils.execute(['ip', 'link', 'show', 'dev', device],
                          root_helper=self.root_helper)
        except RuntimeError:
            return False
        return True

    def interface_exists_on_bridge(self, bridge, interface):
        directory = '/sys/class/net/%s/brif' % bridge
        for filename in os.listdir(directory):
            if filename == interface:
                return True
        return False

    def get_bridge_name(self, network_id):
        if not network_id:
            LOG.warning("Invalid Network ID, will lead to incorrect bridge"
                        "name")
        bridge_name = self.br_name_prefix + network_id[0:11]
        return bridge_name

    def get_subinterface_name(self, vlan_id):
        if not vlan_id:
            LOG.warning("Invalid VLAN ID, will lead to incorrect "
                        "subinterface name")
        subinterface_name = '%s.%s' % (self.physical_interface, vlan_id)
        return subinterface_name

    def get_tap_device_name(self, interface_id):
        if not interface_id:
            LOG.warning("Invalid Interface ID, will lead to incorrect "
                        "tap device name")
        tap_device_name = TAP_INTERFACE_PREFIX + interface_id[0:11]
        return tap_device_name

    def get_all_quantum_bridges(self):
        quantum_bridge_list = []
        bridge_list = os.listdir(BRIDGE_FS)
        for bridge in bridge_list:
            if bridge.startswith(BRIDGE_NAME_PREFIX):
                quantum_bridge_list.append(bridge)
        return quantum_bridge_list

    def get_interfaces_on_bridge(self, bridge_name):
        if self.device_exists(bridge_name):
            bridge_interface_path = BRIDGE_INTERFACES_FS.replace(
                BRIDGE_NAME_PLACEHOLDER, bridge_name)
            return os.listdir(bridge_interface_path)

    def _get_prefixed_ip_link_devices(self, prefix):
        prefixed_devices = []
        retval = utils.execute(['ip', 'link'], root_helper=self.root_helper)
        rows = retval.split('\n')
        for row in rows:
            values = row.split(':')
            if (len(values) > 2):
                value = values[1].strip(' ')
                if (value.startswith(prefix)):
                    prefixed_devices.append(value)
        return prefixed_devices

    def _get_prefixed_tap_devices(self, prefix):
        prefixed_devices = []
        retval = utils.execute(['ip', 'tuntap'], root_helper=self.root_helper)
        rows = retval.split('\n')
        for row in rows:
            split_row = row.split(':')
            if split_row[0].startswith(prefix):
                prefixed_devices.append(split_row[0])
        return prefixed_devices

    def get_all_tap_devices(self):
        try:
            return self._get_prefixed_tap_devices(TAP_INTERFACE_PREFIX)
        except RuntimeError:
            return self._get_prefixed_ip_link_devices(TAP_INTERFACE_PREFIX)

    def get_all_gateway_devices(self):
        try:
            return self._get_prefixed_tap_devices(GATEWAY_INTERFACE_PREFIX)
        except RuntimeError:
            return self._get_prefixed_ip_link_devices(GATEWAY_INTERFACE_PREFIX)

    def get_bridge_for_tap_device(self, tap_device_name):
        bridges = self.get_all_quantum_bridges()
        for bridge in bridges:
            interfaces = self.get_interfaces_on_bridge(bridge)
            if tap_device_name in interfaces:
                return bridge

        return None

    def is_device_on_bridge(self, device_name):
        if not device_name:
            return False
        else:
            bridge_port_path = BRIDGE_PORT_FS_FOR_DEVICE.replace(
                DEVICE_NAME_PLACEHOLDER, device_name)
            return os.path.exists(bridge_port_path)

    def ensure_vlan_bridge(self, network_id, vlan_id):
        """Create a vlan and bridge unless they already exist."""
        interface = self.ensure_vlan(vlan_id)
        bridge_name = self.get_bridge_name(network_id)
        self.ensure_bridge(bridge_name, interface)
        return interface

    def ensure_vlan(self, vlan_id):
        """Create a vlan unless it already exists."""
        interface = self.get_subinterface_name(vlan_id)
        if not self.device_exists(interface):
            LOG.debug("Creating subinterface %s for VLAN %s on interface %s" %
                      (interface, vlan_id, self.physical_interface))
            if utils.execute(['ip', 'link', 'add', 'link',
                              self.physical_interface,
                              'name', interface, 'type', 'vlan', 'id',
                              vlan_id], root_helper=self.root_helper):
                return
            if utils.execute(['ip', 'link', 'set',
                              interface, 'up'], root_helper=self.root_helper):
                return
            LOG.debug("Done creating subinterface %s" % interface)
        return interface

    def ensure_bridge(self, bridge_name, interface):
        """
        Create a bridge unless it already exists.
        """
        if not self.device_exists(bridge_name):
            LOG.debug("Starting bridge %s for subinterface %s" % (bridge_name,
                                                                  interface))
            if utils.execute(['brctl', 'addbr', bridge_name],
                             root_helper=self.root_helper):
                return
            if utils.execute(['brctl', 'setfd', bridge_name,
                              str(0)], root_helper=self.root_helper):
                return
            if utils.execute(['brctl', 'stp', bridge_name,
                              'off'], root_helper=self.root_helper):
                return
            if utils.execute(['ip', 'link', 'set', bridge_name,
                              'up'], root_helper=self.root_helper):
                return
            LOG.debug("Done starting bridge %s for subinterface %s" %
                      (bridge_name, interface))

        # Check if the interface is part of the bridge
        if not self.interface_exists_on_bridge(bridge_name, interface):
            utils.execute(['brctl', 'addif', bridge_name, interface],
                          root_helper=self.root_helper)

    def add_tap_interface(self, network_id, vlan_id, tap_device_name):
        """
        If a VIF has been plugged into a network, this function will
        add the corresponding tap device to the relevant bridge
        """
        if not tap_device_name:
            return False

        if not self.device_exists(tap_device_name):
            LOG.debug("Tap device: %s does not exist on this host, skipped" %
                      tap_device_name)
            return False

        current_bridge_name = self.get_bridge_for_tap_device(tap_device_name)
        bridge_name = self.get_bridge_name(network_id)
        if bridge_name == current_bridge_name:
            return False
        LOG.debug("Adding device %s to bridge %s" % (tap_device_name,
                                                     bridge_name))
        if current_bridge_name:
            if utils.execute(['brctl', 'delif', current_bridge_name,
                              tap_device_name], root_helper=self.root_helper):
                return False

        self.ensure_vlan_bridge(network_id, vlan_id)
        if utils.execute(['brctl', 'addif', bridge_name, tap_device_name],
                         root_helper=self.root_helper):
            return False
        LOG.debug("Done adding device %s to bridge %s" % (tap_device_name,
                                                          bridge_name))
        return True

    def add_interface(self, network_id, vlan_id, interface_id):
        if not interface_id:
            """
            Since the VIF id is null, no VIF is plugged into this port
            no more processing is required
            """
            return False
        if interface_id.startswith(GATEWAY_INTERFACE_PREFIX):
            return self.add_tap_interface(network_id, vlan_id, interface_id)
        else:
            tap_device_name = self.get_tap_device_name(interface_id)
            return self.add_tap_interface(network_id, vlan_id, tap_device_name)

    def delete_vlan_bridge(self, bridge_name):
        if self.device_exists(bridge_name):
            interfaces_on_bridge = self.get_interfaces_on_bridge(bridge_name)
            for interface in interfaces_on_bridge:
                self.remove_interface(bridge_name, interface)
                if interface.startswith(self.physical_interface):
                    self.delete_vlan(interface)

            LOG.debug("Deleting bridge %s" % bridge_name)
            if utils.execute(['ip', 'link', 'set', bridge_name, 'down'],
                             root_helper=self.root_helper):
                return
            if utils.execute(['brctl', 'delbr', bridge_name],
                             root_helper=self.root_helper):
                return
            LOG.debug("Done deleting bridge %s" % bridge_name)

        else:
            LOG.error("Cannot delete bridge %s, does not exist" % bridge_name)

    def remove_interface(self, bridge_name, interface_name):
        if self.device_exists(bridge_name):
            if not self.is_device_on_bridge(interface_name):
                return True
            LOG.debug("Removing device %s from bridge %s" %
                      (interface_name, bridge_name))
            if utils.execute(['brctl', 'delif', bridge_name, interface_name],
                             root_helper=self.root_helper):
                return False
            LOG.debug("Done removing device %s from bridge %s" %
                      (interface_name, bridge_name))
            return True
        else:
            LOG.debug("Cannot remove device %s, bridge %s does not exist" %
                      (interface_name, bridge_name))
            return False

    def delete_vlan(self, interface):
        if self.device_exists(interface):
            LOG.debug("Deleting subinterface %s for vlan" % interface)
            if utils.execute(['ip', 'link', 'set', interface, 'down'],
                             root_helper=self.root_helper):
                return
            if utils.execute(['ip', 'link', 'delete', interface],
                             root_helper=self.root_helper):
                return
            LOG.debug("Done deleting subinterface %s" % interface)


class LinuxBridgeRpcCallbacks():

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, context, linux_br):
        self.context = context
        self.linux_br = linux_br

    def network_delete(self, context, **kwargs):
        LOG.debug("network_delete received")
        network_id = kwargs.get('network_id')
        bridge_name = self.linux_br.get_bridge_name(network_id)
        # (TODO) garyk delete the bridge interface
        LOG.debug("Delete %s", bridge_name)

    def port_update(self, context, **kwargs):
        LOG.debug("port_update received")
        port = kwargs.get('port')
        if port['admin_state_up']:
            vlan_id = kwargs.get('vlan_id')
            # create the networking for the port
            self.linux_br.add_interface(port['network_id'],
                                        vlan_id,
                                        port['id'])
        else:
            bridge_name = self.linux_br.get_bridge_name(port['network_id'])
            tap_device_name = self.linux_br.get_tap_device_name(port['id'])
            self.linux_br.remove_interface(bridge_name, tap_device_name)

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return dispatcher.RpcDispatcher([self])


class LinuxBridgeQuantumAgentDB:

    def __init__(self, br_name_prefix, physical_interface, polling_interval,
                 reconnect_interval, root_helper, target_v2_api,
                 db_connection_url):
        self.polling_interval = polling_interval
        self.root_helper = root_helper
        self.setup_linux_bridge(br_name_prefix, physical_interface)
        self.target_v2_api = target_v2_api
        self.reconnect_interval = reconnect_interval
        self.db_connected = False
        self.db_connection_url = db_connection_url

    def setup_linux_bridge(self, br_name_prefix, physical_interface):
        self.linux_br = LinuxBridge(br_name_prefix, physical_interface,
                                    self.root_helper)

    def process_port_binding(self, network_id, interface_id, vlan_id):
        return self.linux_br.add_interface(network_id, vlan_id, interface_id)

    def remove_port_binding(self, network_id, interface_id):
        bridge_name = self.linux_br.get_bridge_name(network_id)
        tap_device_name = self.linux_br.get_tap_device_name(interface_id)
        return self.linux_br.remove_interface(bridge_name, tap_device_name)

    def process_unplugged_interfaces(self, plugged_interfaces):
        """
        If there are any tap devices that are not corresponding to the
        list of attached VIFs, then those are corresponding to recently
        unplugged VIFs, so we need to remove those tap devices from their
        current bridge association
        """
        plugged_tap_device_names = []
        plugged_gateway_device_names = []
        for interface in plugged_interfaces:
            if interface.startswith(GATEWAY_INTERFACE_PREFIX):
                """
                The name for the gateway devices is set by the linux net
                driver, hence we use the name as is
                """
                plugged_gateway_device_names.append(interface)
            else:
                tap_device_name = self.linux_br.get_tap_device_name(interface)
                plugged_tap_device_names.append(tap_device_name)

        LOG.debug("plugged tap device names %s" % plugged_tap_device_names)
        for tap_device in self.linux_br.get_all_tap_devices():
            if tap_device not in plugged_tap_device_names:
                current_bridge_name = (
                    self.linux_br.get_bridge_for_tap_device(tap_device))
                if current_bridge_name:
                    self.linux_br.remove_interface(current_bridge_name,
                                                   tap_device)

        for gw_device in self.linux_br.get_all_gateway_devices():
            if gw_device not in plugged_gateway_device_names:
                current_bridge_name = (
                    self.linux_br.get_bridge_for_tap_device(gw_device))
                if current_bridge_name:
                    self.linux_br.remove_interface(current_bridge_name,
                                                   gw_device)

    def process_deleted_networks(self, vlan_bindings):
        current_quantum_networks = vlan_bindings.keys()
        current_quantum_bridge_names = []
        for network in current_quantum_networks:
            bridge_name = self.linux_br.get_bridge_name(network)
            current_quantum_bridge_names.append(bridge_name)

        quantum_bridges_on_this_host = self.linux_br.get_all_quantum_bridges()
        for bridge in quantum_bridges_on_this_host:
            if bridge not in current_quantum_bridge_names:
                self.linux_br.delete_vlan_bridge(bridge)

    def manage_networks_on_host(self, db,
                                old_vlan_bindings,
                                old_port_bindings):
        vlan_bindings = {}
        try:
            vlan_binds = db.vlan_bindings.all()
        except Exception as e:
            LOG.info("Unable to get vlan bindings! Exception: %s" % e)
            self.db_connected = False
            return {VLAN_BINDINGS: {},
                    PORT_BINDINGS: []}

        vlans_string = ""
        for bind in vlan_binds:
            entry = {'network_id': bind.network_id, 'vlan_id': bind.vlan_id}
            vlan_bindings[bind.network_id] = entry
            vlans_string = "%s %s" % (vlans_string, entry)

        port_bindings = []
        try:
            port_binds = db.ports.all()
        except Exception as e:
            LOG.info("Unable to get port bindings! Exception: %s" % e)
            self.db_connected = False
            return {VLAN_BINDINGS: {},
                    PORT_BINDINGS: []}

        all_bindings = {}
        for bind in port_binds:
            append_entry = False
            if self.target_v2_api:
                all_bindings[bind.id] = bind
                entry = {'network_id': bind.network_id,
                         'uuid': bind.id,
                         'status': bind.status,
                         'interface_id': bind.id}
                append_entry = bind.admin_state_up
            else:
                all_bindings[bind.uuid] = bind
                entry = {'network_id': bind.network_id, 'state': bind.state,
                         'op_status': bind.op_status, 'uuid': bind.uuid,
                         'interface_id': bind.interface_id}
                append_entry = bind.state == 'ACTIVE'
            if append_entry:
                port_bindings.append(entry)

        plugged_interfaces = []
        ports_string = ""
        for pb in port_bindings:
            ports_string = "%s %s" % (ports_string, pb)
            port_id = pb['uuid']
            interface_id = pb['interface_id']

            vlan_id = str(vlan_bindings[pb['network_id']]['vlan_id'])
            if self.process_port_binding(pb['network_id'],
                                         interface_id,
                                         vlan_id):
                if self.target_v2_api:
                    all_bindings[port_id].status = OP_STATUS_UP
                else:
                    all_bindings[port_id].op_status = OP_STATUS_UP

            plugged_interfaces.append(interface_id)

        if old_port_bindings != port_bindings:
            LOG.debug("Port-bindings: %s" % ports_string)

        self.process_unplugged_interfaces(plugged_interfaces)

        if old_vlan_bindings != vlan_bindings:
            LOG.debug("VLAN-bindings: %s" % vlans_string)

        self.process_deleted_networks(vlan_bindings)

        try:
            db.commit()
        except Exception as e:
            LOG.info("Unable to update database! Exception: %s" % e)
            db.rollback()
            vlan_bindings = {}
            port_bindings = []

        return {VLAN_BINDINGS: vlan_bindings,
                PORT_BINDINGS: port_bindings}

    def daemon_loop(self):
        old_vlan_bindings = {}
        old_port_bindings = []
        self.db_connected = False

        while True:
            if not self.db_connected:
                time.sleep(self.reconnect_interval)
                db = SqlSoup(self.db_connection_url)
                self.db_connected = True
                LOG.info("Connecting to database \"%s\" on %s" %
                         (db.engine.url.database, db.engine.url.host))
            bindings = self.manage_networks_on_host(db,
                                                    old_vlan_bindings,
                                                    old_port_bindings)
            old_vlan_bindings = bindings[VLAN_BINDINGS]
            old_port_bindings = bindings[PORT_BINDINGS]
            time.sleep(self.polling_interval)


class LinuxBridgeQuantumAgentRPC:

    def __init__(self, br_name_prefix, physical_interface, polling_interval,
                 root_helper):
        self.polling_interval = polling_interval
        self.root_helper = root_helper
        self.setup_linux_bridge(br_name_prefix, physical_interface)
        self.setup_rpc(physical_interface)

    def setup_rpc(self, physical_interface):
        mac = utils.get_interface_mac(physical_interface)
        self.agent_id = '%s%s' % ('lb', (mac.replace(":", "")))
        self.topic = topics.AGENT
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)

        # RPC network init
        self.context = context.RequestContext('quantum', 'quantum',
                                              is_admin=False)
        # Handle updates from service
        self.callbacks = LinuxBridgeRpcCallbacks(self.context,
                                                 self.linux_br)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)
        self.udev = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(self.udev)
        monitor.filter_by('net')

    def setup_linux_bridge(self, br_name_prefix, physical_interface):
        self.linux_br = LinuxBridge(br_name_prefix, physical_interface,
                                    self.root_helper)

    def process_port_binding(self, network_id, interface_id, vlan_id):
        return self.linux_br.add_interface(network_id, vlan_id, interface_id)

    def remove_port_binding(self, network_id, interface_id):
        bridge_name = self.linux_br.get_bridge_name(network_id)
        tap_device_name = self.linux_br.get_tap_device_name(interface_id)
        return self.linux_br.remove_interface(bridge_name, tap_device_name)

    def update_devices(self, registered_devices):
        devices = self.udev_get_all_tap_devices()
        if devices == registered_devices:
            return
        added = devices - registered_devices
        removed = registered_devices - devices
        return {'current': devices,
                'added': added,
                'removed': removed}

    def udev_get_all_tap_devices(self):
        devices = set()
        for device in self.udev.list_devices(subsystem='net'):
            name = self.udev_get_name(device)
            if self.is_tap_device(name):
                devices.add(name)
        return devices

    def is_tap_device(self, name):
        return name.startswith(TAP_INTERFACE_PREFIX)

    def udev_get_name(self, device):
        return device.sys_name

    def process_network_devices(self, device_info):
        resync_a = False
        resync_b = False
        if 'added' in device_info:
            resync_a = self.treat_devices_added(device_info['added'])
        if 'removed' in device_info:
            resync_b = self.treat_devices_removed(device_info['removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def treat_devices_added(self, devices):
        resync = False
        for device in devices:
            LOG.info("Port %s added", device)
            try:
                details = self.plugin_rpc.get_device_details(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug("Unable to get port details for %s: %s", device, e)
                resync = True
                continue
            if 'port_id' in details:
                LOG.info("Port %s updated. Details: %s", device, details)
                if details['admin_state_up']:
                    # create the networking for the port
                    self.process_port_binding(details['network_id'],
                                              details['port_id'],
                                              details['vlan_id'])
                else:
                    self.remove_port_binding(details['network_id'],
                                             details['port_id'])
            else:
                LOG.debug("Device %s not defined on plugin", device)
        return resync

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info("Attachment %s removed", device)
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug("port_removed failed for %s: %s", device, e)
                resync = True
            if details['exists']:
                LOG.info("Port %s updated.", device)
                # Nothing to do regarding local networking
            else:
                LOG.debug("Device %s not defined on plugin", device)
        return resync

    def daemon_loop(self):
        sync = True
        devices = set()

        LOG.info("LinuxBridge Agent RPC Daemon Started!")

        while True:
            start = time.time()
            if sync:
                LOG.info("Agent out of sync with plugin!")
                devices.clear()
                sync = False

            device_info = self.update_devices(devices)

            # notify plugin about device deltas
            if device_info:
                LOG.debug("Agent loop has new devices!")
                # If treat devices fails - indicates must resync with plugin
                sync = self.process_network_devices(device_info)
                devices = device_info['current']

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval (%s vs. %s)!",
                          self.polling_interval, elapsed)


def main():
    cfg.CONF(args=sys.argv, project='quantum')

    # (TODO) gary - swap with common logging
    logging_config.setup_logging(cfg.CONF)

    br_name_prefix = BRIDGE_NAME_PREFIX
    physical_interface = cfg.CONF.LINUX_BRIDGE.physical_interface
    polling_interval = cfg.CONF.AGENT.polling_interval
    reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
    root_helper = cfg.CONF.AGENT.root_helper
    rpc = cfg.CONF.AGENT.rpc
    if not cfg.CONF.AGENT.target_v2_api:
        rpc = False

    if rpc:
        plugin = LinuxBridgeQuantumAgentRPC(br_name_prefix,
                                            physical_interface,
                                            polling_interval,
                                            root_helper)
    else:
        db_connection_url = cfg.CONF.DATABASE.sql_connection
        target_v2_api = cfg.CONF.AGENT.target_v2_api
        plugin = LinuxBridgeQuantumAgentDB(br_name_prefix,
                                           physical_interface,
                                           polling_interval,
                                           reconnect_interval,
                                           root_helper,
                                           target_v2_api,
                                           db_connection_url)
    LOG.info("Agent initialized successfully, now running... ")
    plugin.daemon_loop()
    sys.exit(0)

if __name__ == "__main__":
    eventlet.monkey_patch()
    main()
