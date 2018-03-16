#!/usr/bin/env python
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
# Performs per host Linux Bridge configuration for Neutron.
# Based on the structure of the OpenVSwitch agent in the
# Neutron OpenVSwitch Plugin.

import sys

import netaddr
from neutron_lib import constants
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service
from oslo_utils import excutils
from six import moves

from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import exceptions
from neutron.common import profiler as setup_profiler
from neutron.common import topics
from neutron.common import utils
from neutron.conf.agent import common as agent_config
from neutron.plugins.common import utils as p_utils
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron.plugins.ml2.drivers.agent import config as cagt_config  # noqa
from neutron.plugins.ml2.drivers.l2pop.rpc_manager \
    import l2population_rpc as l2pop_rpc
from neutron.plugins.ml2.drivers.linuxbridge.agent import arp_protect
from neutron.plugins.ml2.drivers.linuxbridge.agent.common import config  # noqa
from neutron.plugins.ml2.drivers.linuxbridge.agent.common \
    import constants as lconst
from neutron.plugins.ml2.drivers.linuxbridge.agent.common \
    import utils as lb_utils
from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_agent_extension_api as agent_extension_api
from neutron.plugins.ml2.drivers.linuxbridge.agent \
    import linuxbridge_capabilities


LOG = logging.getLogger(__name__)

LB_AGENT_BINARY = 'neutron-linuxbridge-agent'
BRIDGE_NAME_PREFIX = "brq"
MAX_VLAN_POSTFIX_LEN = 5
VXLAN_INTERFACE_PREFIX = "vxlan-"

IPTABLES_DRIVERS = [
    'iptables',
    'iptables_hybrid',
    'neutron.agent.linux.iptables_firewall.IptablesFirewallDriver',
    'neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver'
]


class LinuxBridgeManager(amb.CommonAgentManagerBase):
    def __init__(self, bridge_mappings, interface_mappings):
        super(LinuxBridgeManager, self).__init__()
        self.bridge_mappings = bridge_mappings
        self.interface_mappings = interface_mappings
        self.validate_interface_mappings()
        self.validate_bridge_mappings()
        self.ip = ip_lib.IPWrapper()
        self.agent_api = None
        # VXLAN related parameters:
        self.local_ip = cfg.CONF.VXLAN.local_ip
        self.vxlan_mode = lconst.VXLAN_NONE
        if cfg.CONF.VXLAN.enable_vxlan:
            device = self.get_local_ip_device()
            self.validate_vxlan_group_with_local_ip()
            self.local_int = device.name
            self.check_vxlan_support()

    def validate_interface_mappings(self):
        for physnet, interface in self.interface_mappings.items():
            if not ip_lib.device_exists(interface):
                LOG.error("Interface %(intf)s for physical network %(net)s"
                          " does not exist. Agent terminated!",
                          {'intf': interface, 'net': physnet})
                sys.exit(1)

    def validate_bridge_mappings(self):
        for physnet, bridge in self.bridge_mappings.items():
            if not ip_lib.device_exists(bridge):
                LOG.error("Bridge %(brq)s for physical network %(net)s"
                          " does not exist. Agent terminated!",
                          {'brq': bridge, 'net': physnet})
                sys.exit(1)

    def _is_valid_multicast_range(self, mrange):
        try:
            addr, vxlan_min, vxlan_max = mrange.split(':')
            if int(vxlan_min) > int(vxlan_max):
                raise ValueError()
            try:
                local_ver = netaddr.IPAddress(self.local_ip).version
                n_addr = netaddr.IPAddress(addr)
                if not n_addr.is_multicast() or n_addr.version != local_ver:
                    raise ValueError()
            except netaddr.core.AddrFormatError:
                raise ValueError()
        except ValueError:
            return False
        return True

    def validate_vxlan_group_with_local_ip(self):
        for r in cfg.CONF.VXLAN.multicast_ranges:
            if not self._is_valid_multicast_range(r):
                LOG.error("Invalid multicast_range %(r)s. Must be in "
                          "<multicast address>:<vni_min>:<vni_max> format and "
                          "addresses must be in the same family as local IP "
                          "%(loc)s.", {'r': r, 'loc': self.local_ip})
                sys.exit(1)
        if not cfg.CONF.VXLAN.vxlan_group:
            return
        try:
            ip_addr = netaddr.IPAddress(self.local_ip)
            # Ensure the configured group address/range is valid and multicast
            group_net = netaddr.IPNetwork(cfg.CONF.VXLAN.vxlan_group)
            if not group_net.is_multicast():
                raise ValueError()
            if not ip_addr.version == group_net.version:
                raise ValueError()
        except (netaddr.core.AddrFormatError, ValueError):
            LOG.error("Invalid VXLAN Group: %(group)s, must be an address "
                      "or network (in CIDR notation) in a multicast "
                      "range of the same address family as local_ip: "
                      "%(ip)s",
                      {'group': cfg.CONF.VXLAN.vxlan_group,
                       'ip': self.local_ip})
            sys.exit(1)

    def get_local_ip_device(self):
        """Return the device with local_ip on the host."""
        device = self.ip.get_device_by_ip(self.local_ip)
        if not device:
            LOG.error("Tunneling cannot be enabled without the local_ip "
                      "bound to an interface on the host. Please "
                      "configure local_ip %s on the host interface to "
                      "be used for tunneling and restart the agent.",
                      self.local_ip)
            sys.exit(1)
        return device

    @staticmethod
    def get_bridge_name(network_id):
        if not network_id:
            LOG.warning("Invalid Network ID, will lead to incorrect "
                        "bridge name")
        bridge_name = BRIDGE_NAME_PREFIX + \
            network_id[:lconst.RESOURCE_ID_LENGTH]
        return bridge_name

    def get_subinterface_name(self, physical_interface, vlan_id):
        if not vlan_id:
            LOG.warning("Invalid VLAN ID, will lead to incorrect "
                        "subinterface name")
        vlan_postfix = '.%s' % vlan_id

        # For the vlan subinterface name prefix we use:
        # * the physical_interface, if len(physical_interface) +
        #   len(vlan_postifx) <= 15 for backward compatibility reasons
        #   Example: physical_interface = eth0
        #            prefix = eth0.1
        #            prefix = eth0.1111
        #
        # * otherwise a unique hash per physical_interface to help debugging
        #   Example: physical_interface = long_interface
        #            prefix = longHASHED.1
        #            prefix = longHASHED.1111
        #
        # Remark: For some physical_interface values, the used prefix can be
        # both, the physical_interface itself or a hash, depending
        # on the vlan_postfix length.
        # Example: physical_interface = mix_interface
        #          prefix = mix_interface.1 (backward compatible)
        #          prefix = mix_iHASHED.1111
        if (len(physical_interface) + len(vlan_postfix) >
            constants.DEVICE_NAME_MAX_LEN):
            physical_interface = p_utils.get_interface_name(
                physical_interface, max_len=(constants.DEVICE_NAME_MAX_LEN -
                                             MAX_VLAN_POSTFIX_LEN))
        return "%s%s" % (physical_interface, vlan_postfix)

    @staticmethod
    def get_tap_device_name(interface_id):
        return lb_utils.get_tap_device_name(interface_id)

    def get_vxlan_device_name(self, segmentation_id):
        if 0 <= int(segmentation_id) <= constants.MAX_VXLAN_VNI:
            return VXLAN_INTERFACE_PREFIX + str(segmentation_id)
        else:
            LOG.warning("Invalid Segmentation ID: %s, will lead to "
                        "incorrect vxlan device name", segmentation_id)

    @staticmethod
    def _match_multicast_range(segmentation_id):
        for mrange in cfg.CONF.VXLAN.multicast_ranges:
            addr, vxlan_min, vxlan_max = mrange.split(':')
            if int(vxlan_min) <= segmentation_id <= int(vxlan_max):
                return addr

    def get_vxlan_group(self, segmentation_id):
        mcast_addr = self._match_multicast_range(segmentation_id)
        if mcast_addr:
            net = netaddr.IPNetwork(mcast_addr)
        else:
            net = netaddr.IPNetwork(cfg.CONF.VXLAN.vxlan_group)
        # Map the segmentation ID to (one of) the group address(es)
        return str(net.network +
                   (int(segmentation_id) & int(net.hostmask)))

    def get_deletable_bridges(self):
        bridge_list = bridge_lib.get_bridge_names()
        bridges = {b for b in bridge_list if b.startswith(BRIDGE_NAME_PREFIX)}
        bridges.difference_update(self.bridge_mappings.values())
        return bridges

    def get_tap_devices_count(self, bridge_name):
        if_list = bridge_lib.BridgeDevice(bridge_name).get_interfaces()
        return len([interface for interface in if_list if
                    interface.startswith(constants.TAP_DEVICE_PREFIX)])

    def ensure_vlan_bridge(self, network_id, phy_bridge_name,
                           physical_interface, vlan_id):
        """Create a vlan and bridge unless they already exist."""
        interface = self.ensure_vlan(physical_interface, vlan_id)
        if phy_bridge_name:
            return self.ensure_bridge(phy_bridge_name)
        else:
            bridge_name = self.get_bridge_name(network_id)
            if self.ensure_bridge(bridge_name, interface):
                return interface

    def ensure_vxlan_bridge(self, network_id, segmentation_id):
        """Create a vxlan and bridge unless they already exist."""
        interface = self.ensure_vxlan(segmentation_id)
        if not interface:
            LOG.error("Failed creating vxlan interface for "
                      "%(segmentation_id)s",
                      {segmentation_id: segmentation_id})
            return
        bridge_name = self.get_bridge_name(network_id)
        self.ensure_bridge(bridge_name, interface, update_interface=False)
        return interface

    def get_interface_details(self, interface, ip_version):
        device = self.ip.device(interface)
        ips = device.addr.list(scope='global',
                               ip_version=ip_version)

        # Update default gateway if necessary
        gateway = device.route.get_gateway(scope='global',
                                           ip_version=ip_version)
        return ips, gateway

    def ensure_flat_bridge(self, network_id, phy_bridge_name,
                           physical_interface):
        """Create a non-vlan bridge unless it already exists."""
        if phy_bridge_name:
            return self.ensure_bridge(phy_bridge_name)
        else:
            bridge_name = self.get_bridge_name(network_id)
            if self.ensure_bridge(bridge_name, physical_interface):
                return physical_interface

    def ensure_local_bridge(self, network_id, phy_bridge_name):
        """Create a local bridge unless it already exists."""
        if phy_bridge_name:
            bridge_name = phy_bridge_name
        else:
            bridge_name = self.get_bridge_name(network_id)
        return self.ensure_bridge(bridge_name)

    def ensure_vlan(self, physical_interface, vlan_id):
        """Create a vlan unless it already exists."""
        interface = self.get_subinterface_name(physical_interface, vlan_id)
        if not ip_lib.device_exists(interface):
            LOG.debug("Creating subinterface %(interface)s for "
                      "VLAN %(vlan_id)s on interface "
                      "%(physical_interface)s",
                      {'interface': interface, 'vlan_id': vlan_id,
                       'physical_interface': physical_interface})
            try:
                int_vlan = self.ip.add_vlan(interface, physical_interface,
                                            vlan_id)
            except RuntimeError:
                with excutils.save_and_reraise_exception() as ctxt:
                    if ip_lib.vlan_in_use(vlan_id):
                        ctxt.reraise = False
                        LOG.error("Unable to create VLAN interface for "
                                  "VLAN ID %s because it is in use by "
                                  "another interface.", vlan_id)
                        return
            int_vlan.disable_ipv6()
            int_vlan.link.set_up()
            LOG.debug("Done creating subinterface %s", interface)
        return interface

    def ensure_vxlan(self, segmentation_id):
        """Create a vxlan unless it already exists."""
        interface = self.get_vxlan_device_name(segmentation_id)
        if not ip_lib.device_exists(interface):
            LOG.debug("Creating vxlan interface %(interface)s for "
                      "VNI %(segmentation_id)s",
                      {'interface': interface,
                       'segmentation_id': segmentation_id})
            args = {'dev': self.local_int,
                    'srcport': (cfg.CONF.VXLAN.udp_srcport_min,
                                cfg.CONF.VXLAN.udp_srcport_max),
                    'dstport': cfg.CONF.VXLAN.udp_dstport,
                    'ttl': cfg.CONF.VXLAN.ttl}
            if cfg.CONF.VXLAN.tos:
                args['tos'] = cfg.CONF.VXLAN.tos
                if cfg.CONF.AGENT.dscp or cfg.CONF.AGENT.dscp_inherit:
                    LOG.warning('The deprecated tos option in group VXLAN '
                                'is set and takes precedence over dscp and '
                                'dscp_inherit in group AGENT.')
            elif cfg.CONF.AGENT.dscp_inherit:
                args['tos'] = 'inherit'
            elif cfg.CONF.AGENT.dscp:
                args['tos'] = int(cfg.CONF.AGENT.dscp) << 2

            if self.vxlan_mode == lconst.VXLAN_MCAST:
                args['group'] = self.get_vxlan_group(segmentation_id)
            if cfg.CONF.VXLAN.l2_population:
                args['proxy'] = cfg.CONF.VXLAN.arp_responder

            try:
                int_vxlan = self.ip.add_vxlan(interface, segmentation_id,
                                              **args)
            except RuntimeError:
                with excutils.save_and_reraise_exception() as ctxt:
                    # perform this check after an attempt rather than before
                    # to avoid excessive lookups and a possible race condition.
                    if ip_lib.vxlan_in_use(segmentation_id):
                        ctxt.reraise = False
                        LOG.error("Unable to create VXLAN interface for "
                                  "VNI %s because it is in use by another "
                                  "interface.", segmentation_id)
                        return None
            int_vxlan.disable_ipv6()
            int_vxlan.link.set_up()
            LOG.debug("Done creating vxlan interface %s", interface)
        return interface

    def _update_interface_ip_details(self, destination, source, ips, gateway):
        dst_device = self.ip.device(destination)
        src_device = self.ip.device(source)

        # Append IP's to bridge if necessary
        if ips:
            for ip in ips:
                # If bridge ip address already exists, then don't add
                # otherwise will report error
                to = utils.cidr_to_ip(ip['cidr'])
                if not dst_device.addr.list(to=to):
                    dst_device.addr.add(cidr=ip['cidr'])

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
                src_device.addr.delete(cidr=ip['cidr'])

    def update_interface_ip_details(self, destination, source):
        # Returns True if there were IPs or a gateway moved
        updated = False
        for ip_version in (constants.IP_VERSION_4, constants.IP_VERSION_6):
            ips, gateway = self.get_interface_details(source, ip_version)
            if ips or gateway:
                self._update_interface_ip_details(destination, source, ips,
                                                  gateway)
                updated = True

        return updated

    def _bridge_exists_and_ensure_up(self, bridge_name):
        """Check if the bridge exists and make sure it is up."""
        br = ip_lib.IPDevice(bridge_name)
        br.set_log_fail_as_error(False)
        try:
            # If the device doesn't exist this will throw a RuntimeError
            br.link.set_up()
        except RuntimeError:
            return False
        return True

    def ensure_bridge(self, bridge_name, interface=None,
                      update_interface=True):
        """Create a bridge unless it already exists."""
        # _bridge_exists_and_ensure_up instead of device_exists is used here
        # because there are cases where the bridge exists but it's not UP,
        # for example:
        # 1) A greenthread was executing this function and had not yet executed
        # "ip link set bridge_name up" before eventlet switched to this
        # thread running the same function
        # 2) The Nova VIF driver was running concurrently and had just created
        #    the bridge, but had not yet put it UP
        if not self._bridge_exists_and_ensure_up(bridge_name):
            LOG.debug("Starting bridge %(bridge_name)s for subinterface "
                      "%(interface)s",
                      {'bridge_name': bridge_name, 'interface': interface})
            bridge_device = bridge_lib.BridgeDevice.addbr(bridge_name)
            if bridge_device.setfd(0):
                return
            if bridge_device.disable_stp():
                return
            if bridge_device.link.set_up():
                return
            LOG.debug("Done starting bridge %(bridge_name)s for "
                      "subinterface %(interface)s",
                      {'bridge_name': bridge_name, 'interface': interface})
        else:
            bridge_device = bridge_lib.BridgeDevice(bridge_name)

        if not interface:
            return bridge_name

        # Update IP info if necessary
        if update_interface:
            self.update_interface_ip_details(bridge_name, interface)

        # Check if the interface is part of the bridge
        if not bridge_device.owns_interface(interface):
            try:
                # Check if the interface is not enslaved in another bridge
                bridge = bridge_lib.BridgeDevice.get_interface_bridge(
                    interface)
                if bridge:
                    bridge.delif(interface)

                bridge_device.addif(interface)
            except Exception as e:
                LOG.error("Unable to add %(interface)s to %(bridge_name)s"
                          "! Exception: %(e)s",
                          {'interface': interface, 'bridge_name': bridge_name,
                           'e': e})
                return
        return bridge_name

    def ensure_physical_in_bridge(self, network_id,
                                  network_type,
                                  physical_network,
                                  segmentation_id):
        if network_type == constants.TYPE_VXLAN:
            if self.vxlan_mode == lconst.VXLAN_NONE:
                LOG.error("Unable to add vxlan interface for network %s",
                          network_id)
                return
            return self.ensure_vxlan_bridge(network_id, segmentation_id)

        # NOTE(nick-ma-z): Obtain mappings of physical bridge and interfaces
        physical_bridge = self.bridge_mappings.get(physical_network)
        physical_interface = self.interface_mappings.get(physical_network)
        if not physical_bridge and not physical_interface:
            LOG.error("No bridge or interface mappings"
                      " for physical network %s",
                      physical_network)
            return
        if network_type == constants.TYPE_FLAT:
            return self.ensure_flat_bridge(network_id, physical_bridge,
                                           physical_interface)
        elif network_type == constants.TYPE_VLAN:
            return self.ensure_vlan_bridge(network_id, physical_bridge,
                                           physical_interface,
                                           segmentation_id)
        else:
            LOG.error("Unknown network_type %(network_type)s for network "
                      "%(network_id)s.", {network_type: network_type,
                                          network_id: network_id})

    def add_tap_interface(self, network_id, network_type, physical_network,
                          segmentation_id, tap_device_name, device_owner, mtu):
        """Add tap interface and handle interface missing exceptions."""
        try:
            return self._add_tap_interface(network_id, network_type,
                                           physical_network, segmentation_id,
                                           tap_device_name, device_owner, mtu)
        except Exception:
            with excutils.save_and_reraise_exception() as ctx:
                if not ip_lib.device_exists(tap_device_name):
                    # the exception was likely a side effect of the tap device
                    # being removed during handling so we just return false
                    # like we would if it didn't exist to begin with.
                    ctx.reraise = False
                    return False

    def _add_tap_interface(self, network_id, network_type, physical_network,
                          segmentation_id, tap_device_name, device_owner, mtu):
        """Add tap interface.

        If a VIF has been plugged into a network, this function will
        add the corresponding tap device to the relevant bridge.
        """
        if not ip_lib.device_exists(tap_device_name):
            LOG.debug("Tap device: %s does not exist on "
                      "this host, skipped", tap_device_name)
            return False

        bridge_name = self.bridge_mappings.get(physical_network)
        if not bridge_name:
            bridge_name = self.get_bridge_name(network_id)

        if network_type == constants.TYPE_LOCAL:
            self.ensure_local_bridge(network_id, bridge_name)
        elif not self.ensure_physical_in_bridge(network_id,
                                                network_type,
                                                physical_network,
                                                segmentation_id):
            return False
        if mtu:  # <-None with device_details from older neutron servers.
            # we ensure the MTU here because libvirt does not set the
            # MTU of a bridge it creates and the tap device it creates will
            # inherit from the bridge its plugged into, which will be 1500
            # at the time. See bug/1684326 for details.
            self._set_tap_mtu(tap_device_name, mtu)
        # Avoid messing with plugging devices into a bridge that the agent
        # does not own
        if not device_owner.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX):
            # Check if device needs to be added to bridge
            if not bridge_lib.BridgeDevice.get_interface_bridge(
                tap_device_name):
                data = {'tap_device_name': tap_device_name,
                        'bridge_name': bridge_name}
                LOG.debug("Adding device %(tap_device_name)s to bridge "
                          "%(bridge_name)s", data)
                if bridge_lib.BridgeDevice(bridge_name).addif(tap_device_name):
                    return False
        else:
            data = {'tap_device_name': tap_device_name,
                    'device_owner': device_owner,
                    'bridge_name': bridge_name}
            LOG.debug("Skip adding device %(tap_device_name)s to "
                      "%(bridge_name)s. It is owned by %(device_owner)s and "
                      "thus added elsewhere.", data)
        return True

    def _set_tap_mtu(self, tap_device_name, mtu):
        ip_lib.IPDevice(tap_device_name).link.set_mtu(mtu)

    def plug_interface(self, network_id, network_segment, tap_name,
                       device_owner):
        return self.add_tap_interface(network_id, network_segment.network_type,
                                      network_segment.physical_network,
                                      network_segment.segmentation_id,
                                      tap_name, device_owner,
                                      network_segment.mtu)

    def delete_bridge(self, bridge_name):
        bridge_device = bridge_lib.BridgeDevice(bridge_name)
        if bridge_device.exists():
            physical_interfaces = set(self.interface_mappings.values())
            interfaces_on_bridge = bridge_device.get_interfaces()
            for interface in interfaces_on_bridge:
                self.remove_interface(bridge_name, interface)

                if interface.startswith(VXLAN_INTERFACE_PREFIX):
                    self.delete_interface(interface)
                else:
                    # Match the vlan/flat interface in the bridge.
                    # If the bridge has an IP, it mean that this IP was moved
                    # from the current interface, which also mean that this
                    # interface was not created by the agent.
                    updated = self.update_interface_ip_details(interface,
                                                               bridge_name)
                    if not updated and interface not in physical_interfaces:
                        self.delete_interface(interface)

            try:
                LOG.debug("Deleting bridge %s", bridge_name)
                if bridge_device.link.set_down():
                    return
                if bridge_device.delbr():
                    return
                LOG.debug("Done deleting bridge %s", bridge_name)
            except RuntimeError:
                with excutils.save_and_reraise_exception() as ctxt:
                    if not bridge_device.exists():
                        # the exception was likely a side effect of the bridge
                        # being removed by nova during handling,
                        # so we just return
                        ctxt.reraise = False
                        LOG.debug("Cannot delete bridge %s; it does not exist",
                                  bridge_name)
                        return
        else:
            LOG.debug("Cannot delete bridge %s; it does not exist",
                      bridge_name)

    def remove_interface(self, bridge_name, interface_name):
        bridge_device = bridge_lib.BridgeDevice(bridge_name)
        if bridge_device.exists():
            if not bridge_device.owns_interface(interface_name):
                return True
            LOG.debug("Removing device %(interface_name)s from bridge "
                      "%(bridge_name)s",
                      {'interface_name': interface_name,
                       'bridge_name': bridge_name})
            try:
                bridge_device.delif(interface_name)
                LOG.debug("Done removing device %(interface_name)s from "
                          "bridge %(bridge_name)s",
                          {'interface_name': interface_name,
                           'bridge_name': bridge_name})
                return True
            except RuntimeError:
                with excutils.save_and_reraise_exception() as ctxt:
                    if not bridge_device.owns_interface(interface_name):
                        # the exception was likely a side effect of the tap
                        # being deleted by some other agent during handling
                        ctxt.reraise = False
                        LOG.debug("Cannot remove %(interface_name)s from "
                                  "%(bridge_name)s. It is not on the bridge.",
                                  {'interface_name': interface_name,
                                   'bridge_name': bridge_name})
                        return False
        else:
            LOG.debug("Cannot remove device %(interface_name)s bridge "
                      "%(bridge_name)s does not exist",
                      {'interface_name': interface_name,
                       'bridge_name': bridge_name})
            return False

    def delete_interface(self, interface):
        device = self.ip.device(interface)
        if device.exists():
            LOG.debug("Deleting interface %s",
                      interface)
            device.link.set_down()
            device.link.delete()
            LOG.debug("Done deleting interface %s", interface)

    def get_devices_modified_timestamps(self, devices):
        # NOTE(kevinbenton): we aren't returning real timestamps here. We
        # are returning interface indexes instead which change when the
        # interface is removed/re-added. This works for the direct
        # comparison the common agent loop performs with these.
        # See bug/1622833 for details.
        return {d: bridge_lib.get_interface_ifindex(d) for d in devices}

    def get_all_devices(self):
        devices = set()
        for device in bridge_lib.get_bridge_names():
            if device.startswith(constants.TAP_DEVICE_PREFIX):
                devices.add(device)
        return devices

    def vxlan_ucast_supported(self):
        if not cfg.CONF.VXLAN.l2_population:
            return False
        if not ip_lib.iproute_arg_supported(
                ['bridge', 'fdb'], 'append'):
            LOG.warning('Option "%(option)s" must be supported by command '
                        '"%(command)s" to enable %(mode)s mode',
                        {'option': 'append',
                         'command': 'bridge fdb',
                         'mode': 'VXLAN UCAST'})
            return False

        test_iface = None
        for seg_id in moves.range(1, constants.MAX_VXLAN_VNI + 1):
            if (ip_lib.device_exists(self.get_vxlan_device_name(seg_id))
                    or ip_lib.vxlan_in_use(seg_id)):
                continue
            test_iface = self.ensure_vxlan(seg_id)
            break
        else:
            LOG.error('No valid Segmentation ID to perform UCAST test.')
            return False

        try:
            bridge_lib.FdbInterface.append(constants.FLOODING_ENTRY[0],
                                           test_iface, '1.1.1.1',
                                           log_fail_as_error=False)
            return True
        except RuntimeError:
            return False
        finally:
            self.delete_interface(test_iface)

    def vxlan_mcast_supported(self):
        if not cfg.CONF.VXLAN.vxlan_group:
            LOG.warning('VXLAN muticast group(s) must be provided in '
                        'vxlan_group option to enable VXLAN MCAST mode')
            return False
        if not ip_lib.iproute_arg_supported(
                ['ip', 'link', 'add', 'type', 'vxlan'],
                'proxy'):
            LOG.warning('Option "%(option)s" must be supported by command '
                        '"%(command)s" to enable %(mode)s mode',
                        {'option': 'proxy',
                         'command': 'ip link add type vxlan',
                         'mode': 'VXLAN MCAST'})

            return False
        return True

    def check_vxlan_support(self):
        self.vxlan_mode = lconst.VXLAN_NONE

        if self.vxlan_ucast_supported():
            self.vxlan_mode = lconst.VXLAN_UCAST
        elif self.vxlan_mcast_supported():
            self.vxlan_mode = lconst.VXLAN_MCAST
        else:
            raise exceptions.VxlanNetworkUnsupported()
        LOG.debug('Using %s VXLAN mode', self.vxlan_mode)

    def fdb_ip_entry_exists(self, mac, ip, interface):
        ip_version = utils.get_ip_version(ip)
        entry = ip_lib.dump_neigh_entries(ip_version, interface, dst=ip,
                                          lladdr=mac)
        return entry != []

    def fdb_bridge_entry_exists(self, mac, interface, agent_ip=None):
        entries = bridge_lib.FdbInterface.show(interface)
        if not agent_ip:
            return mac in entries

        return (agent_ip in entries and mac in entries)

    def add_fdb_ip_entry(self, mac, ip, interface):
        if cfg.CONF.VXLAN.arp_responder:
            ip_lib.add_neigh_entry(ip, mac, interface)

    def remove_fdb_ip_entry(self, mac, ip, interface):
        if cfg.CONF.VXLAN.arp_responder:
            ip_lib.delete_neigh_entry(ip, mac, interface)

    def add_fdb_entries(self, agent_ip, ports, interface):
        for mac, ip in ports:
            if mac != constants.FLOODING_ENTRY[0]:
                self.add_fdb_ip_entry(mac, ip, interface)
                bridge_lib.FdbInterface.replace(mac, interface, agent_ip,
                                                check_exit_code=False)
            elif self.vxlan_mode == lconst.VXLAN_UCAST:
                if self.fdb_bridge_entry_exists(mac, interface):
                    bridge_lib.FdbInterface.append(mac, interface, agent_ip,
                                                   check_exit_code=False)
                else:
                    bridge_lib.FdbInterface.add(mac, interface, agent_ip,
                                                check_exit_code=False)

    def remove_fdb_entries(self, agent_ip, ports, interface):
        for mac, ip in ports:
            if mac != constants.FLOODING_ENTRY[0]:
                self.remove_fdb_ip_entry(mac, ip, interface)
                bridge_lib.FdbInterface.delete(mac, interface, agent_ip,
                                               check_exit_code=False)
            elif self.vxlan_mode == lconst.VXLAN_UCAST:
                bridge_lib.FdbInterface.delete(mac, interface, agent_ip,
                                               check_exit_code=False)

    def get_agent_id(self):
        if self.bridge_mappings:
            mac = ip_lib.get_device_mac(
                list(self.bridge_mappings.values())[0])
        else:
            devices = self.ip.get_devices(True)
            for device in devices:
                mac = ip_lib.get_device_mac(device.name)
                if mac:
                    break
            else:
                LOG.error("Unable to obtain MAC address for unique ID. "
                          "Agent terminated!")
                sys.exit(1)
        return 'lb%s' % mac.replace(":", "")

    def get_agent_configurations(self):
        configurations = {'bridge_mappings': self.bridge_mappings,
                          'interface_mappings': self.interface_mappings
                          }
        if self.vxlan_mode != lconst.VXLAN_NONE:
            configurations['tunneling_ip'] = self.local_ip
            configurations['tunnel_types'] = [constants.TYPE_VXLAN]
            configurations['l2_population'] = cfg.CONF.VXLAN.l2_population
        return configurations

    def get_rpc_callbacks(self, context, agent, sg_agent):
        return LinuxBridgeRpcCallbacks(context, agent, sg_agent)

    def get_agent_api(self, **kwargs):
        if self.agent_api:
            return self.agent_api
        sg_agent = kwargs.get("sg_agent")
        iptables_manager = self._get_iptables_manager(sg_agent)
        self.agent_api = agent_extension_api.LinuxbridgeAgentExtensionAPI(
            iptables_manager)
        return self.agent_api

    def _get_iptables_manager(self, sg_agent):
        if not sg_agent:
            return None
        if cfg.CONF.SECURITYGROUP.firewall_driver in IPTABLES_DRIVERS:
            return sg_agent.firewall.iptables

    def get_rpc_consumers(self):
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.NETWORK, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        if cfg.CONF.VXLAN.l2_population:
            consumers.append([topics.L2POPULATION, topics.UPDATE])
        return consumers

    def ensure_port_admin_state(self, tap_name, admin_state_up):
        LOG.debug("Setting admin_state_up to %s for device %s",
                  admin_state_up, tap_name)
        if admin_state_up:
            ip_lib.IPDevice(tap_name).link.set_up()
        else:
            ip_lib.IPDevice(tap_name).link.set_down()

    def setup_arp_spoofing_protection(self, device, device_details):
        arp_protect.setup_arp_spoofing_protection(device, device_details)

    def delete_arp_spoofing_protection(self, devices):
        arp_protect.delete_arp_spoofing_protection(devices)

    def delete_unreferenced_arp_protection(self, current_devices):
        arp_protect.delete_unreferenced_arp_protection(current_devices)

    def get_extension_driver_type(self):
        return lconst.EXTENSION_DRIVER_TYPE


class LinuxBridgeRpcCallbacks(
    sg_rpc.SecurityGroupAgentRpcCallbackMixin,
    l2pop_rpc.L2populationRpcCallBackMixin,
    amb.CommonAgentManagerRpcCallBackBase):

    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC
    #   1.3 Added param devices_to_update to security_groups_provider_updated
    #   1.4 Added support for network_update
    target = oslo_messaging.Target(version='1.4')

    def network_delete(self, context, **kwargs):
        LOG.debug("network_delete received")
        network_id = kwargs.get('network_id')

        # NOTE(nick-ma-z): Don't remove pre-existing user-defined bridges
        if network_id in self.network_map:
            phynet = self.network_map[network_id].physical_network
            if phynet and phynet in self.agent.mgr.bridge_mappings:
                LOG.info("Physical network %s is defined in "
                         "bridge_mappings and cannot be deleted.",
                         network_id)
                return

        bridge_name = self.agent.mgr.get_bridge_name(network_id)
        LOG.debug("Delete %s", bridge_name)
        self.agent.mgr.delete_bridge(bridge_name)
        self.network_map.pop(network_id, None)

    def port_update(self, context, **kwargs):
        port_id = kwargs['port']['id']
        device_name = self.agent.mgr.get_tap_device_name(port_id)
        # Put the device name in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications there is no guarantee the notifications are
        # processed in the same order as the relevant API requests.
        self.updated_devices.add(device_name)
        LOG.debug("port_update RPC received for port: %s", port_id)

    def network_update(self, context, **kwargs):
        network_id = kwargs['network']['id']
        LOG.debug("network_update message processed for network "
                  "%(network_id)s, with ports: %(ports)s",
                  {'network_id': network_id,
                   'ports': self.agent.network_ports[network_id]})
        for port_data in self.agent.network_ports[network_id]:
            self.updated_devices.add(port_data['device'])

    def fdb_add(self, context, fdb_entries):
        LOG.debug("fdb_add received")
        for network_id, values in fdb_entries.items():
            segment = self.network_map.get(network_id)
            if not segment:
                return

            if segment.network_type != constants.TYPE_VXLAN:
                return

            interface = self.agent.mgr.get_vxlan_device_name(
                segment.segmentation_id)

            agent_ports = values.get('ports')
            for agent_ip, ports in agent_ports.items():
                if agent_ip == self.agent.mgr.local_ip:
                    continue

                self.agent.mgr.add_fdb_entries(agent_ip,
                                               ports,
                                               interface)

    def fdb_remove(self, context, fdb_entries):
        LOG.debug("fdb_remove received")
        for network_id, values in fdb_entries.items():
            segment = self.network_map.get(network_id)
            if not segment:
                return

            if segment.network_type != constants.TYPE_VXLAN:
                return

            interface = self.agent.mgr.get_vxlan_device_name(
                segment.segmentation_id)

            agent_ports = values.get('ports')
            for agent_ip, ports in agent_ports.items():
                if agent_ip == self.agent.mgr.local_ip:
                    continue

                self.agent.mgr.remove_fdb_entries(agent_ip,
                                                  ports,
                                                  interface)

    def _fdb_chg_ip(self, context, fdb_entries):
        LOG.debug("update chg_ip received")
        for network_id, agent_ports in fdb_entries.items():
            segment = self.network_map.get(network_id)
            if not segment:
                return

            if segment.network_type != constants.TYPE_VXLAN:
                return

            interface = self.agent.mgr.get_vxlan_device_name(
                segment.segmentation_id)

            for agent_ip, state in agent_ports.items():
                if agent_ip == self.agent.mgr.local_ip:
                    continue

                after = state.get('after', [])
                for mac, ip in after:
                    self.agent.mgr.add_fdb_ip_entry(mac, ip, interface)

                before = state.get('before', [])
                for mac, ip in before:
                    self.agent.mgr.remove_fdb_ip_entry(mac, ip, interface)

    def fdb_update(self, context, fdb_entries):
        LOG.debug("fdb_update received")
        for action, values in fdb_entries.items():
            method = '_fdb_' + action
            if not hasattr(self, method):
                raise NotImplementedError()

            getattr(self, method)(context, values)


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    agent_config.setup_privsep()
    try:
        interface_mappings = helpers.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.physical_interface_mappings)
    except ValueError as e:
        LOG.error("Parsing physical_interface_mappings failed: %s. "
                  "Agent terminated!", e)
        sys.exit(1)
    LOG.info("Interface mappings: %s", interface_mappings)

    try:
        bridge_mappings = helpers.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.bridge_mappings)
    except ValueError as e:
        LOG.error("Parsing bridge_mappings failed: %s. "
                  "Agent terminated!", e)
        sys.exit(1)
    LOG.info("Bridge mappings: %s", bridge_mappings)

    manager = LinuxBridgeManager(bridge_mappings, interface_mappings)
    linuxbridge_capabilities.register()

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = ca.CommonAgentLoop(manager, polling_interval, quitting_rpc_timeout,
                               constants.AGENT_TYPE_LINUXBRIDGE,
                               LB_AGENT_BINARY)
    setup_profiler.setup("neutron-linuxbridge-agent", cfg.CONF.host)
    LOG.info("Agent initialized successfully, now running... ")
    launcher = service.launch(cfg.CONF, agent)
    launcher.wait()
