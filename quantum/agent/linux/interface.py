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
    cfg.StrOpt('ryu_api_host',
               default='127.0.0.1:8080',
               help='Openflow Ryu REST API host:port')
]


class LinuxInterfaceDriver(object):
    __metaclass__ = abc.ABCMeta

    # from linux IF_NAMESIZE
    DEV_NAME_LEN = 14
    DEV_NAME_PREFIX = 'tap'

    def __init__(self, conf):
        self.conf = conf

    def init_l3(self, port, device_name):
        """Set the L3 settings for the interface using data from the port."""
        device = ip_lib.IPDevice(device_name,
                                 self.conf.root_helper,
                                 port.network.id)

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

    def get_device_name(self, port):
        return (self.DEV_NAME_PREFIX + port.id)[:self.DEV_NAME_LEN]

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

        if not ip_lib.device_exists(device_name,
                                    self.conf.root_helper,
                                    namespace=network_id):

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

            ip = ip_lib.IPWrapper(self.conf.root_helper)
            device = ip.device(device_name)
            device.link.set_address(mac_address)
            if self.conf.network_device_mtu:
                device.link.set_mtu(self.conf.network_device_mtu)

            namespace = ip.ensure_namespace(network_id)
            namespace.add_device_to_namespace(device)
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

    DEV_NAME_PREFIX = 'dhc'

    def plug(self, network_id, port_id, device_name, mac_address):
        """Plugin the interface."""
        if not ip_lib.device_exists(device_name,
                                    self.conf.root_helper,
                                    namespace=network_id):
            ip = ip_lib.IPWrapper(self.conf.root_helper)

            tap_name = device_name.replace(self.DEV_NAME_PREFIX, 'tap')
            root_veth, dhcp_veth = ip.add_veth(tap_name, device_name)
            root_veth.link.set_address(mac_address)

            namespace = ip.ensure_namespace(network_id)
            namespace.add_device_to_namespace(root_veth)

            root_veth.link.set_up()
            dhcp_veth.link.set_up()

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


class RyuInterfaceDriver(OVSInterfaceDriver):
    """Driver for creating a Ryu OVS interface."""

    def __init__(self, conf):
        super(RyuInterfaceDriver, self).__init__(conf)

        from ryu.app.client import OFPClient
        LOG.debug('ryu rest host %s', self.conf.ryu_api_host)
        self.ryu_client = OFPClient(self.conf.ryu_api_host)

        self.check_bridge_exists(self.conf.ovs_integration_bridge)
        self.ovs_br = ovs_lib.OVSBridge(self.conf.ovs_integration_bridge,
                                        self.conf.root_helper)
        self.datapath_id = self.ovs_br.get_datapath_id()

    def plug(self, network_id, port_id, device_name, mac_address):
        """Plug in the interface."""
        super(RyuInterfaceDriver, self).plug(network_id, port_id, device_name,
                                             mac_address)

        port_no = self.ovs_br.get_port_ofport(device_name)
        self.ryu_client.create_port(network_id, self.datapath_id, port_no)
