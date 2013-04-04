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

import os
import sys
import time

import eventlet
from oslo.config import cfg
import pyudev

from quantum.agent.linux import ip_lib
from quantum.agent.linux import utils
from quantum.agent import rpc as agent_rpc
from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.common import config as logging_config
from quantum.common import constants
from quantum.common import topics
from quantum.common import utils as q_utils
from quantum import context
from quantum.openstack.common import log as logging
from quantum.openstack.common import loopingcall
from quantum.openstack.common.rpc import dispatcher
from quantum.plugins.linuxbridge.common import config  # noqa
from quantum.plugins.linuxbridge.common import constants as lconst


LOG = logging.getLogger(__name__)

BRIDGE_NAME_PREFIX = "brq"
TAP_INTERFACE_PREFIX = "tap"
BRIDGE_FS = "/sys/devices/virtual/net/"
BRIDGE_NAME_PLACEHOLDER = "bridge_name"
BRIDGE_INTERFACES_FS = BRIDGE_FS + BRIDGE_NAME_PLACEHOLDER + "/brif/"
DEVICE_NAME_PLACEHOLDER = "device_name"
BRIDGE_PORT_FS_FOR_DEVICE = BRIDGE_FS + DEVICE_NAME_PLACEHOLDER + "/brport"


class LinuxBridgeManager:
    def __init__(self, interface_mappings, root_helper):
        self.interface_mappings = interface_mappings
        self.root_helper = root_helper
        self.ip = ip_lib.IPWrapper(self.root_helper)

        self.udev = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(self.udev)
        monitor.filter_by('net')

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
            LOG.warning(_("Invalid Network ID, will lead to incorrect bridge"
                          "name"))
        bridge_name = BRIDGE_NAME_PREFIX + network_id[0:11]
        return bridge_name

    def get_subinterface_name(self, physical_interface, vlan_id):
        if not vlan_id:
            LOG.warning(_("Invalid VLAN ID, will lead to incorrect "
                          "subinterface name"))
        subinterface_name = '%s.%s' % (physical_interface, vlan_id)
        return subinterface_name

    def get_tap_device_name(self, interface_id):
        if not interface_id:
            LOG.warning(_("Invalid Interface ID, will lead to incorrect "
                          "tap device name"))
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

    def ensure_vlan_bridge(self, network_id, physical_interface, vlan_id):
        """Create a vlan and bridge unless they already exist."""
        interface = self.ensure_vlan(physical_interface, vlan_id)
        bridge_name = self.get_bridge_name(network_id)
        self.ensure_bridge(bridge_name, interface)
        return interface

    def get_interface_details(self, interface):
        device = self.ip.device(interface)
        ips = device.addr.list(scope='global')

        # Update default gateway if necessary
        gateway = device.route.get_gateway(scope='global')
        return ips, gateway

    def ensure_flat_bridge(self, network_id, physical_interface):
        """Create a non-vlan bridge unless it already exists."""
        bridge_name = self.get_bridge_name(network_id)
        ips, gateway = self.get_interface_details(physical_interface)
        self.ensure_bridge(bridge_name, physical_interface, ips, gateway)
        return physical_interface

    def ensure_local_bridge(self, network_id):
        """Create a local bridge unless it already exists."""
        bridge_name = self.get_bridge_name(network_id)
        self.ensure_bridge(bridge_name)

    def ensure_vlan(self, physical_interface, vlan_id):
        """Create a vlan unless it already exists."""
        interface = self.get_subinterface_name(physical_interface, vlan_id)
        if not self.device_exists(interface):
            LOG.debug(_("Creating subinterface %(interface)s for "
                        "VLAN %(vlan_id)s on interface "
                        "%(physical_interface)s"),
                      locals())
            if utils.execute(['ip', 'link', 'add', 'link',
                              physical_interface,
                              'name', interface, 'type', 'vlan', 'id',
                              vlan_id], root_helper=self.root_helper):
                return
            if utils.execute(['ip', 'link', 'set',
                              interface, 'up'], root_helper=self.root_helper):
                return
            LOG.debug(_("Done creating subinterface %s"), interface)
        return interface

    def update_interface_ip_details(self, destination, source, ips,
                                    gateway):
        if ips or gateway:
            dst_device = self.ip.device(destination)
            src_device = self.ip.device(source)

        # Append IP's to bridge if necessary
        if ips:
            for ip in ips:
                dst_device.addr.add(ip_version=ip['ip_version'],
                                    cidr=ip['cidr'],
                                    broadcast=ip['broadcast'])

        if gateway:
            # Ensure that the gateway can be updated by changing the metric
            metric = 100
            if 'metric' in gateway:
                metric = gateway['metric'] - 1
            dst_device.route.add_gateway(gateway=gateway['gateway'],
                                         metric=metric)
            src_device.route.delete_gateway(gateway=gateway['gateway'])

        # Remove IP's from interface
        if ips:
            for ip in ips:
                src_device.addr.delete(ip_version=ip['ip_version'],
                                       cidr=ip['cidr'])

    def ensure_bridge(self, bridge_name, interface=None, ips=None,
                      gateway=None):
        """
        Create a bridge unless it already exists.
        """
        if not self.device_exists(bridge_name):
            LOG.debug(_("Starting bridge %(bridge_name)s for subinterface "
                        "%(interface)s"), locals())
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
            LOG.debug(_("Done starting bridge %(bridge_name)s for "
                        "subinterface %(interface)s"),
                      locals())

        if not interface:
            return

        # Update IP info if necessary
        self.update_interface_ip_details(bridge_name, interface, ips, gateway)

        # Check if the interface is part of the bridge
        if not self.interface_exists_on_bridge(bridge_name, interface):
            try:
                utils.execute(['brctl', 'addif', bridge_name, interface],
                              root_helper=self.root_helper)
            except Exception as e:
                LOG.error(_("Unable to add %(interface)s to %(bridge_name)s! "
                            "Exception: %(e)s"), locals())
                return

    def ensure_physical_in_bridge(self, network_id,
                                  physical_network,
                                  vlan_id):
        physical_interface = self.interface_mappings.get(physical_network)
        if not physical_interface:
            LOG.error(_("No mapping for physical network %s"),
                      physical_network)
            return False

        if int(vlan_id) == lconst.FLAT_VLAN_ID:
            self.ensure_flat_bridge(network_id, physical_interface)
        else:
            self.ensure_vlan_bridge(network_id, physical_interface,
                                    vlan_id)
        return True

    def add_tap_interface(self, network_id, physical_network, vlan_id,
                          tap_device_name):
        """
        If a VIF has been plugged into a network, this function will
        add the corresponding tap device to the relevant bridge
        """
        if not self.device_exists(tap_device_name):
            LOG.debug(_("Tap device: %s does not exist on "
                        "this host, skipped"), tap_device_name)
            return False

        bridge_name = self.get_bridge_name(network_id)
        if int(vlan_id) == lconst.LOCAL_VLAN_ID:
            self.ensure_local_bridge(network_id)
        else:
            result = self.ensure_physical_in_bridge(network_id,
                                                    physical_network,
                                                    vlan_id)
            if not result:
                return False

        # Check if device needs to be added to bridge
        tap_device_in_bridge = self.get_bridge_for_tap_device(tap_device_name)
        if not tap_device_in_bridge:
            msg = _("Adding device %(tap_device_name)s to bridge "
                    "%(bridge_name)s") % locals()
            LOG.debug(msg)
            if utils.execute(['brctl', 'addif', bridge_name, tap_device_name],
                             root_helper=self.root_helper):
                return False
        else:
            msg = _("%(tap_device_name)s already exists on bridge "
                    "%(bridge_name)s") % locals()
            LOG.debug(msg)
        return True

    def add_interface(self, network_id, physical_network, vlan_id,
                      port_id):
        tap_device_name = self.get_tap_device_name(port_id)
        return self.add_tap_interface(network_id,
                                      physical_network, vlan_id,
                                      tap_device_name)

    def delete_vlan_bridge(self, bridge_name):
        if self.device_exists(bridge_name):
            interfaces_on_bridge = self.get_interfaces_on_bridge(bridge_name)
            for interface in interfaces_on_bridge:
                self.remove_interface(bridge_name, interface)
                for physical_interface in self.interface_mappings.itervalues():
                    if physical_interface == interface:
                        # This is a flat network => return IP's from bridge to
                        # interface
                        ips, gateway = self.get_interface_details(bridge_name)
                        self.update_interface_ip_details(interface,
                                                         bridge_name,
                                                         ips, gateway)
                    else:
                        if interface.startswith(physical_interface):
                            self.delete_vlan(interface)

            LOG.debug(_("Deleting bridge %s"), bridge_name)
            if utils.execute(['ip', 'link', 'set', bridge_name, 'down'],
                             root_helper=self.root_helper):
                return
            if utils.execute(['brctl', 'delbr', bridge_name],
                             root_helper=self.root_helper):
                return
            LOG.debug(_("Done deleting bridge %s"), bridge_name)

        else:
            LOG.error(_("Cannot delete bridge %s, does not exist"),
                      bridge_name)

    def remove_interface(self, bridge_name, interface_name):
        if self.device_exists(bridge_name):
            if not self.is_device_on_bridge(interface_name):
                return True
            LOG.debug(_("Removing device %(interface_name)s from bridge "
                        "%(bridge_name)s"), locals())
            if utils.execute(['brctl', 'delif', bridge_name, interface_name],
                             root_helper=self.root_helper):
                return False
            LOG.debug(_("Done removing device %(interface_name)s from bridge "
                        "%(bridge_name)s"), locals())
            return True
        else:
            LOG.debug(_("Cannot remove device %(interface_name)s bridge "
                        "%(bridge_name)s does not exist"), locals())
            return False

    def delete_vlan(self, interface):
        if self.device_exists(interface):
            LOG.debug(_("Deleting subinterface %s for vlan"), interface)
            if utils.execute(['ip', 'link', 'set', interface, 'down'],
                             root_helper=self.root_helper):
                return
            if utils.execute(['ip', 'link', 'delete', interface],
                             root_helper=self.root_helper):
                return
            LOG.debug(_("Done deleting subinterface %s"), interface)

    def update_devices(self, registered_devices):
        devices = self.udev_get_tap_devices()
        if devices == registered_devices:
            return
        added = devices - registered_devices
        removed = registered_devices - devices
        return {'current': devices,
                'added': added,
                'removed': removed}

    def udev_get_tap_devices(self):
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


class LinuxBridgeRpcCallbacks(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'

    def __init__(self, context, agent):
        self.context = context
        self.agent = agent
        self.sg_agent = agent

    def network_delete(self, context, **kwargs):
        LOG.debug(_("network_delete received"))
        network_id = kwargs.get('network_id')
        bridge_name = self.agent.br_mgr.get_bridge_name(network_id)
        LOG.debug(_("Delete %s"), bridge_name)
        self.agent.br_mgr.delete_vlan_bridge(bridge_name)

    def port_update(self, context, **kwargs):
        LOG.debug(_("port_update received"))
        # Check port exists on node
        port = kwargs.get('port')
        tap_device_name = self.agent.br_mgr.get_tap_device_name(port['id'])
        devices = self.agent.br_mgr.udev_get_tap_devices()
        if tap_device_name not in devices:
            return

        if 'security_groups' in port:
            self.sg_agent.refresh_firewall()

        if port['admin_state_up']:
            vlan_id = kwargs.get('vlan_id')
            physical_network = kwargs.get('physical_network')
            # create the networking for the port
            self.agent.br_mgr.add_interface(port['network_id'],
                                            physical_network,
                                            vlan_id,
                                            port['id'])
            # update plugin about port status
            self.agent.plugin_rpc.update_device_up(self.context,
                                                   tap_device_name,
                                                   self.agent.agent_id)
        else:
            bridge_name = self.agent.br_mgr.get_bridge_name(
                port['network_id'])
            self.agent.br_mgr.remove_interface(bridge_name, tap_device_name)
            # update plugin about port status
            self.agent.plugin_rpc.update_device_down(self.context,
                                                     tap_device_name,
                                                     self.agent.agent_id)

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return dispatcher.RpcDispatcher([self])


class LinuxBridgePluginApi(agent_rpc.PluginApi,
                           sg_rpc.SecurityGroupServerRpcApiMixin):
    pass


class LinuxBridgeQuantumAgentRPC(sg_rpc.SecurityGroupAgentRpcMixin):

    def __init__(self, interface_mappings, polling_interval,
                 root_helper):
        self.polling_interval = polling_interval
        self.root_helper = root_helper
        self.setup_linux_bridge(interface_mappings)
        self.agent_state = {
            'binary': 'quantum-linuxbridge-agent',
            'host': cfg.CONF.host,
            'topic': constants.L2_AGENT_TOPIC,
            'configurations': interface_mappings,
            'agent_type': constants.AGENT_TYPE_LINUXBRIDGE,
            'start_flag': True}

        self.setup_rpc(interface_mappings.values())
        self.init_firewall()

    def _report_state(self):
        try:
            devices = len(self.br_mgr.udev_get_tap_devices())
            self.agent_state.get('configurations')['devices'] = devices
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception("Failed reporting state!")

    def setup_rpc(self, physical_interfaces):
        if physical_interfaces:
            mac = utils.get_interface_mac(physical_interfaces[0])
        else:
            devices = ip_lib.IPWrapper(self.root_helper).get_devices(True)
            if devices:
                mac = utils.get_interface_mac(devices[0].name)
            else:
                LOG.error(_("Unable to obtain MAC address for unique ID. "
                          "Agent terminated!"))
                exit(1)
        self.agent_id = '%s%s' % ('lb', (mac.replace(":", "")))
        LOG.info(_("RPC agent_id: %s"), self.agent_id)

        self.topic = topics.AGENT
        self.plugin_rpc = LinuxBridgePluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.callbacks = LinuxBridgeRpcCallbacks(self.context,
                                                 self)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.LoopingCall(self._report_state)
            heartbeat.start(interval=report_interval)

    def setup_linux_bridge(self, interface_mappings):
        self.br_mgr = LinuxBridgeManager(interface_mappings, self.root_helper)

    def remove_port_binding(self, network_id, interface_id):
        bridge_name = self.br_mgr.get_bridge_name(network_id)
        tap_device_name = self.br_mgr.get_tap_device_name(interface_id)
        return self.br_mgr.remove_interface(bridge_name, tap_device_name)

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
        self.prepare_devices_filter(devices)
        for device in devices:
            LOG.debug(_("Port %s added"), device)
            try:
                details = self.plugin_rpc.get_device_details(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"), locals())
                resync = True
                continue
            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         locals())
                if details['admin_state_up']:
                    # create the networking for the port
                    self.br_mgr.add_interface(details['network_id'],
                                              details['physical_network'],
                                              details['vlan_id'],
                                              details['port_id'])
                else:
                    self.remove_port_binding(details['network_id'],
                                             details['port_id'])
            else:
                LOG.info(_("Device %s not defined on plugin"), device)
        return resync

    def treat_devices_removed(self, devices):
        resync = False
        self.remove_devices_filter(devices)
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          locals())
                resync = True
            if details['exists']:
                LOG.info(_("Port %s updated."), device)
                # Nothing to do regarding local networking
            else:
                LOG.debug(_("Device %s not defined on plugin"), device)
        return resync

    def daemon_loop(self):
        sync = True
        devices = set()

        LOG.info(_("LinuxBridge Agent RPC Daemon Started!"))

        while True:
            start = time.time()
            if sync:
                LOG.info(_("Agent out of sync with plugin!"))
                devices.clear()
                sync = False
            device_info = {}
            try:
                device_info = self.br_mgr.update_devices(devices)
            except Exception:
                LOG.exception(_("Update devices failed"))
                sync = True
            try:
                # notify plugin about device deltas
                if device_info:
                    LOG.debug(_("Agent loop has new devices!"))
                    # If treat devices fails - indicates must resync with
                    # plugin
                    sync = self.process_network_devices(device_info)
                    devices = device_info['current']
            except Exception:
                LOG.exception(_("Error in agent loop. Devices info: %s"),
                              device_info)
                sync = True
            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})


def main():
    eventlet.monkey_patch()
    cfg.CONF(project='quantum')

    logging_config.setup_logging(cfg.CONF)
    try:
        interface_mappings = q_utils.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.physical_interface_mappings)
    except ValueError as e:
        LOG.error(_("Parsing physical_interface_mappings failed: %s."
                    " Agent terminated!"), e)
        sys.exit(1)
    LOG.info(_("Interface mappings: %s"), interface_mappings)

    polling_interval = cfg.CONF.AGENT.polling_interval
    root_helper = cfg.CONF.AGENT.root_helper
    plugin = LinuxBridgeQuantumAgentRPC(interface_mappings,
                                        polling_interval,
                                        root_helper)
    LOG.info(_("Agent initialized successfully, now running... "))
    plugin.daemon_loop()
    sys.exit(0)


if __name__ == "__main__":
    main()
