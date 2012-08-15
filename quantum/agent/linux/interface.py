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
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('ovs_integration_bridge',
               default='br-int',
               help='Name of Open vSwitch bridge to use'),
    cfg.StrOpt('network_device_mtu',
               help='MTU setting for device.'),
    cfg.StrOpt('ryu_api_host',
               default='127.0.0.1:8080',
               help='Openflow Ryu REST API host:port'),
    cfg.StrOpt('meta_flavor_driver_mappings',
               help='Mapping between flavor and LinuxInterfaceDriver')
]


class LinuxInterfaceDriver(object):
    __metaclass__ = abc.ABCMeta

    # from linux IF_NAMESIZE
    DEV_NAME_LEN = 14
    DEV_NAME_PREFIX = 'tap'

    def __init__(self, conf):
        self.conf = conf

    def init_l3(self, device_name, ip_cidrs, namespace=None):
        """Set the L3 settings for the interface using data from the port.
           ip_cidrs: list of 'X.X.X.X/YY' strings
        """
        device = ip_lib.IPDevice(device_name, self.conf.root_helper,
                                 namespace=namespace)

        previous = {}
        for address in device.addr.list(scope='global', filters=['permanent']):
            previous[address['cidr']] = address['ip_version']

        # add new addresses
        for ip_cidr in ip_cidrs:

            net = netaddr.IPNetwork(ip_cidr)
            if ip_cidr in previous:
                del previous[ip_cidr]
                continue

            device.addr.add(net.version, ip_cidr, str(net.broadcast))

        # clean up any old addresses
        for ip_cidr, ip_version in previous.items():
            device.addr.delete(ip_version, ip_cidr)

    def check_bridge_exists(self, bridge):
        if not ip_lib.device_exists(bridge):
            raise exceptions.BridgeDoesNotExist(bridge=bridge)

    def get_device_name(self, port):
        return (self.DEV_NAME_PREFIX + port.id)[:self.DEV_NAME_LEN]

    @abc.abstractmethod
    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None):
        """Plug in the interface."""

    @abc.abstractmethod
    def unplug(self, device_name, bridge=None, namespace=None):
        """Unplug the interface."""


class NullDriver(LinuxInterfaceDriver):
    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None):
        pass

    def unplug(self, device_name, bridge=None, namespace=None):
        pass


class OVSInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating an internal interface on an OVS bridge."""

    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None):
        """Plug in the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)

        if not ip_lib.device_exists(device_name,
                                    self.conf.root_helper,
                                    namespace=namespace):

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

        if namespace:
            namespace_obj = ip.ensure_namespace(namespace)
            namespace_obj.add_device_to_namespace(device)
        device.link.set_up()

    def unplug(self, device_name, bridge=None, namespace=None):
        """Unplug the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)
        bridge = ovs_lib.OVSBridge(bridge, self.conf.root_helper)
        bridge.delete_port(device_name)


class BridgeInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating bridge interfaces."""

    DEV_NAME_PREFIX = 'dhc'

    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None):
        """Plugin the interface."""
        if not ip_lib.device_exists(device_name,
                                    self.conf.root_helper,
                                    namespace=namespace):
            ip = ip_lib.IPWrapper(self.conf.root_helper)

            tap_name = device_name.replace(self.DEV_NAME_PREFIX, 'tap')
            root_veth, dhcp_veth = ip.add_veth(tap_name, device_name)
            root_veth.link.set_address(mac_address)

            if namespace:
                namespace_obj = ip.ensure_namespace(namespace)
                namespace_obj.add_device_to_namespace(dhcp_veth)

            root_veth.link.set_up()
            dhcp_veth.link.set_up()

        else:
            LOG.warn(_("Device %s already exists") % device_name)

    def unplug(self, device_name, bridge=None, namespace=None):
        """Unplug the interface."""
        device = ip_lib.IPDevice(device_name, self.conf.root_helper, namespace)
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

    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None):
        """Plug in the interface."""
        super(RyuInterfaceDriver, self).plug(network_id, port_id, device_name,
                                             mac_address, bridge=bridge,
                                             namespace=namespace)
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)
        ovs_br = ovs_lib.OVSBridge(bridge, self.conf.root_helper)
        datapath_id = ovs_br.get_datapath_id()
        port_no = ovs_br.get_port_ofport(device_name)
        self.ryu_client.create_port(network_id, datapath_id, port_no)


class MetaInterfaceDriver(LinuxInterfaceDriver):
    def __init__(self, conf):
        super(MetaInterfaceDriver, self).__init__(conf)
        from quantumclient.v2_0 import client
        self.quantum = client.Client(
            username=self.conf.admin_user,
            password=self.conf.admin_password,
            tenant_name=self.conf.admin_tenant_name,
            auth_url=self.conf.auth_url,
            auth_strategy=self.conf.auth_strategy,
            auth_region=self.conf.auth_region
        )
        self.flavor_driver_map = {}
        for flavor, driver_name in [
                driver_set.split(':')
                for driver_set in
                self.conf.meta_flavor_driver_mappings.split(',')]:
            self.flavor_driver_map[flavor] =\
                self._load_driver(driver_name)

    def _get_driver_by_network_id(self, network_id):
        network = self.quantum.show_network(network_id)
        flavor = network['network']['flavor:id']
        return self.flavor_driver_map[flavor]

    def _get_driver_by_device_name(self, device_name):
        device = ip_lib.IPDevice(device_name, self.conf.root_helper)
        mac_address = device.link.address
        ports = self.quantum.list_ports(mac_address=mac_address)
        if not 'ports' in ports or len(ports['ports']) < 1:
            raise Exception('No port for this device %s' % device_name)
        return self._get_driver_by_network_id(ports['ports'][0]['network_id'])

    def get_device_name(self, port):
        driver = self._get_driver_by_network_id(port.network_id)
        return driver.get_device_name(port)

    def plug(self, network_id, port_id, device_name, mac_address):
        driver = self._get_driver_by_network_id(network_id)
        return driver.plug(network_id, port_id, device_name, mac_address)

    def unplug(self, device_name):
        driver = self._get_driver_by_device_name(device_name)
        return driver.unplug(device_name)

    def _load_driver(self, driver_provider):
        LOG.debug("Driver location:%s", driver_provider)
        # If the plugin can't be found let them know gracefully
        try:
            LOG.info("Loading Driver: %s" % driver_provider)
            plugin_klass = importutils.import_class(driver_provider)
        except ClassNotFound:
            LOG.exception("Error loading driver")
            raise Exception("driver_provider not found.  You can install a "
                            "Driver with: pip install <plugin-name>\n"
                            "Example: pip install quantum-sample-driver")
        return plugin_klass(self.conf)
