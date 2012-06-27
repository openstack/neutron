# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import abc
import logging

import netaddr

from quantum.agent.linux import ip_lib
from quantum.agent.linux import ovs_lib
from quantum.agent.linux import utils
from quantum.common import exceptions
from quantum.openstack.common import cfg

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('ovs_integration_bridge',
               default='br-int',
               help='Name of Open vSwitch bridge to use'),
    cfg.StrOpt('network_device_mtu',
               help='MTU setting for device.'),
]


class LinuxInterfaceDriver(object):
    __metaclass__ = abc.ABCMeta

    # from linux IF_NAMESIZE
    DEV_NAME_LEN = 14

    def __init__(self, conf):
        self.conf = conf

    def init_l3(self, port, device_name):
        """Set the L3 settings for the interface using data from the port."""
        device = ip_lib.IPDevice(device_name, self.conf.root_helper)

        previous = {}
        for address in device.addr.list(scope='global', filters=['permanent']):
            previous[address['cidr']] = address['ip_version']

        # add new addresses
        for fixed_ip in port.fixed_ips:
            subnet = fixed_ip.subnet
            net = netaddr.IPNetwork(subnet.cidr)
            ip_cidr = '%s/%s' % (fixed_ip.ip_address, net.prefixlen)

            if ip_cidr in previous:
                del previous[ip_cidr]
                continue

            device.addr.add(net.version, ip_cidr, str(net.broadcast))

        # clean up any old addresses
        for ip_cidr, ip_version in previous.items():
            device.addr.delete(ip_version, ip_cidr)

    def check_bridge_exists(self, bridge):
        if not ip_lib.device_exists(bridge):
            raise exception.BridgeDoesNotExist(bridge=bridge)

    @abc.abstractmethod
    def plug(self, network_id, port_id, device_name, mac_address):
        """Plug in the interface."""

    @abc.abstractmethod
    def unplug(self, device_name):
        """Unplug the interface."""


class NullDriver(LinuxInterfaceDriver):
    def plug(self, network_id, port_id, device_name, mac_address):
        pass

    def unplug(self, device_name):
        pass


class OVSInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating an OVS interface."""

    def plug(self, network_id, port_id, device_name, mac_address):
        """Plug in the interface."""
        bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)

        if not ip_lib.device_exists(device_name):
            utils.execute(['ovs-vsctl',
                           '--', '--may-exist', 'add-port', bridge,
                           device_name,
                           '--', 'set', 'Interface', device_name,
                           'type=internal',
                           '--', 'set', 'Interface', device_name,
                           'external-ids:iface-id=%s' % port_id,
                           '--', 'set', 'Interface', device_name,
                           'external-ids:iface-status=active',
                           '--', 'set', 'Interface', device_name,
                           'external-ids:attached-mac=%s' %
                           mac_address],
                          self.conf.root_helper)

            device = ip_lib.IPDevice(device_name, self.conf.root_helper)
            device.link.set_address(mac_address)
            if self.conf.network_device_mtu:
                device.link.set_mtu(self.conf.network_device_mtu)
            device.link.set_up()
        else:
            LOG.error(_('Device %s already exists') % device)

    def unplug(self, device_name):
        """Unplug the interface."""
        bridge_name = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge_name)
        bridge = ovs_lib.OVSBridge(bridge_name, self.conf.root_helper)
        bridge.delete_port(device_name)


class BridgeInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating bridge interfaces."""

    BRIDGE_NAME_PREFIX = 'brq'

    def plug(self, network_id, port_id, device_name, mac_address):
        """Plugin the interface."""
        bridge = self.get_bridge(network_id)

        self.check_bridge_exists(bridge)

        if not ip_lib.device_exists(device_name):
            device = ip_lib.IPDevice(device_name, self.conf.root_helper)
            try:
                # First, try with 'ip'
                device.tuntap.add()
            except RuntimeError, e:
                # Second option: tunctl
                utils.execute(['tunctl', '-b', '-t', device_name],
                              self.conf.root_helper)

            device.link.set_address(mac_address)
            device.link.set_up()
        else:
            LOG.warn(_("Device %s already exists") % device_name)

    def unplug(self, device_name):
        """Unplug the interface."""
        device = ip_lib.IPDevice(device_name, self.conf.root_helper)
        try:
            device.link.delete()
            LOG.debug(_("Unplugged interface '%s'") % device_name)
        except RuntimeError:
            LOG.error(_("Failed unplugging interface '%s'") %
                      device_name)

    def get_bridge(self, network_id):
        """Returns the name of the bridge interface."""
        bridge = self.BRIDGE_NAME_PREFIX + network_id[0:11]
        return bridge
