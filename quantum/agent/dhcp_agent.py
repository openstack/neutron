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

import logging
import os
import re
import socket
import sys
import uuid

import eventlet
import netaddr

from quantum.agent import rpc as agent_rpc
from quantum.agent.common import config
from quantum.agent.linux import dhcp
from quantum.agent.linux import interface
from quantum.agent.linux import ip_lib
from quantum.api.v2 import attributes
from quantum.common import exceptions
from quantum.common import topics
from quantum.openstack.common import cfg
from quantum.openstack.common import context
from quantum.openstack.common import importutils
from quantum.openstack.common import jsonutils
from quantum.openstack.common.rpc import proxy

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qdhcp-'


class DhcpAgent(object):
    OPTS = [
        cfg.StrOpt('root_helper', default='sudo'),
        cfg.IntOpt('resync_interval', default=30),
        cfg.StrOpt('dhcp_driver',
                   default='quantum.agent.linux.dhcp.Dnsmasq',
                   help="The driver used to manage the DHCP server."),
        cfg.BoolOpt('use_namespaces', default=True,
                    help="Allow overlapping IP.")
    ]

    def __init__(self, conf):
        self.needs_resync = False
        self.conf = conf
        self.cache = NetworkCache()

        self.dhcp_driver_cls = importutils.import_class(conf.dhcp_driver)
        ctx = context.RequestContext('quantum', 'quantum', is_admin=True)
        self.plugin_rpc = DhcpPluginApi(topics.PLUGIN, ctx)

        self.device_manager = DeviceManager(self.conf, self.plugin_rpc)
        self.notifications = agent_rpc.NotificationDispatcher()
        self.lease_relay = DhcpLeaseRelay(self.update_lease)

    def run(self):
        """Activate the DHCP agent."""
        self.sync_state()
        self.periodic_resync()
        self.lease_relay.start()
        self.notifications.run_dispatch(self)

    def call_driver(self, action, network):
        """Invoke an action on a DHCP driver instance."""
        if self.conf.use_namespaces:
            namespace = NS_PREFIX + network.id
        else:
            namespace = None
        try:
            # the Driver expects something that is duck typed similar to
            # the base models.
            driver = self.dhcp_driver_cls(self.conf,
                                          network,
                                          self.conf.root_helper,
                                          self.device_manager,
                                          namespace)
            getattr(driver, action)()
            return True

        except Exception, e:
            self.needs_resync = True
            LOG.exception('Unable to %s dhcp.' % action)

    def update_lease(self, network_id, ip_address, time_remaining):
        try:
            self.plugin_rpc.update_lease_expiration(network_id, ip_address,
                                                    time_remaining)
        except:
            self.needs_resync = True
            LOG.exception(_('Unable to update lease'))

    def sync_state(self):
        """Sync the local DHCP state with Quantum."""
        LOG.info(_('Synchronizing state'))
        known_networks = set(self.cache.get_network_ids())

        try:
            active_networks = set(self.plugin_rpc.get_active_networks())
            for deleted_id in known_networks - active_networks:
                self.disable_dhcp_helper(deleted_id)

            for network_id in active_networks:
                self.refresh_dhcp_helper(network_id)
        except:
            self.needs_resync = True
            LOG.exception(_('Unable to sync network state.'))

    def _periodic_resync_helper(self):
        """Resync the dhcp state at the configured interval."""
        while True:
            eventlet.sleep(self.conf.resync_interval)
            if self.needs_resync:
                self.needs_resync = False
                self.sync_state()

    def periodic_resync(self):
        """Spawn a thread to periodically resync the dhcp state."""
        eventlet.spawn(self._periodic_resync_helper)

    def enable_dhcp_helper(self, network_id):
        """Enable DHCP for a network that meets enabling criteria."""
        try:
            network = self.plugin_rpc.get_network_info(network_id)
        except:
            self.needs_resync = True
            LOG.exception(_('Network %s RPC info call failed.') % network_id)
            return

        if not network.admin_state_up:
            return

        for subnet in network.subnets:
            if subnet.enable_dhcp:
                if self.call_driver('enable', network):
                    self.cache.put(network)
                break

    def disable_dhcp_helper(self, network_id):
        """Disable DHCP for a network known to the agent."""
        network = self.cache.get_network_by_id(network_id)
        if network:
            if self.call_driver('disable', network):
                self.cache.remove(network)

    def refresh_dhcp_helper(self, network_id):
        """Refresh or disable DHCP for a network depending on the current state
        of the network.

        """
        old_network = self.cache.get_network_by_id(network_id)
        if not old_network:
            # DHCP current not running for network.
            return self.enable_dhcp_helper(network_id)

        try:
            network = self.plugin_rpc.get_network_info(network_id)
        except:
            self.needs_resync = True
            LOG.exception(_('Network %s RPC info call failed.') % network_id)
            return

        old_cidrs = set(s.cidr for s in old_network.subnets if s.enable_dhcp)
        new_cidrs = set(s.cidr for s in network.subnets if s.enable_dhcp)

        if new_cidrs and old_cidrs == new_cidrs:
            self.call_driver('reload_allocations', network)
            self.cache.put(network)
        elif new_cidrs:
            if self.call_driver('restart', network):
                self.cache.put(network)
        else:
            self.disable_dhcp_helper(network.id)

    def network_create_end(self, payload):
        """Handle the network.create.end notification event."""
        network_id = payload['network']['id']
        self.enable_dhcp_helper(network_id)

    def network_update_end(self, payload):
        """Handle the network.update.end notification event."""
        network_id = payload['network']['id']
        if payload['network']['admin_state_up']:
            self.enable_dhcp_helper(network_id)
        else:
            self.disable_dhcp_helper(network_id)

    def network_delete_end(self, payload):
        """Handle the network.delete.end notification event."""
        self.disable_dhcp_helper(payload['network_id'])

    def subnet_update_end(self, payload):
        """Handle the subnet.update.end notification event."""
        network_id = payload['subnet']['network_id']
        self.refresh_dhcp_helper(network_id)

    # Use the update handler for the subnet create event.
    subnet_create_end = subnet_update_end

    def subnet_delete_end(self, payload):
        """Handle the subnet.delete.end notification event."""
        subnet_id = payload['subnet_id']
        network = self.cache.get_network_by_subnet_id(subnet_id)
        if network:
            self.refresh_dhcp_helper(network.id)

    def port_update_end(self, payload):
        """Handle the port.update.end notification event."""
        port = DictModel(payload['port'])
        network = self.cache.get_network_by_id(port.network_id)
        if network:
            self.cache.put_port(port)
            self.call_driver('reload_allocations', network)

    # Use the update handler for the port create event.
    port_create_end = port_update_end

    def port_delete_end(self, payload):
        """Handle the port.delete.end notification event."""
        port = self.cache.get_port_by_id(payload['port_id'])
        if port:
            network = self.cache.get_network_by_id(port.network_id)
            self.cache.remove_port(port)
            self.call_driver('reload_allocations', network)


class DhcpPluginApi(proxy.RpcProxy):
    """Agent side of the dhcp rpc API.

    API version history:
        1.0 - Initial version.

    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, context):
        super(DhcpPluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.context = context
        self.host = socket.gethostname()

    def get_active_networks(self):
        """Make a remote process call to retrieve the active networks."""
        return self.call(self.context,
                         self.make_msg('get_active_networks', host=self.host),
                         topic=self.topic)

    def get_network_info(self, network_id):
        """Make a remote process call to retrieve network info."""
        return DictModel(self.call(self.context,
                                   self.make_msg('get_network_info',
                                                 network_id=network_id,
                                                 host=self.host),
                                   topic=self.topic))

    def get_dhcp_port(self, network_id, device_id):
        """Make a remote process call to create the dhcp port."""
        return DictModel(self.call(self.context,
                                   self.make_msg('get_dhcp_port',
                                                 network_id=network_id,
                                                 device_id=device_id,
                                                 host=self.host),
                                   topic=self.topic))

    def release_dhcp_port(self, network_id, device_id):
        """Make a remote process call to release the dhcp port."""
        return self.call(self.context,
                         self.make_msg('release_dhcp_port',
                                       network_id=network_id,
                                       device_id=device_id,
                                       host=self.host),
                         topic=self.topic)

    def release_port_fixed_ip(self, network_id, device_id, subnet_id):
        """Make a remote process call to release a fixed_ip on the port."""
        return self.call(self.context,
                         self.make_msg('release_port_fixed_ip',
                                       network_id=network_id,
                                       subnet_id=subnet_id,
                                       device_id=device_id,
                                       host=self.host),
                         topic=self.topic)

    def update_lease_expiration(self, network_id, ip_address, lease_remaining):
        """Make a remote process call to update the ip lease expiration."""
        self.cast(self.context,
                  self.make_msg('update_lease_expiration',
                                network_id=network_id,
                                ip_address=ip_address,
                                lease_remaining=lease_remaining,
                                host=self.host),
                  topic=self.topic)


class NetworkCache(object):
    """Agent cache of the current network state."""
    def __init__(self):
        self.cache = {}
        self.subnet_lookup = {}
        self.port_lookup = {}

    def get_network_ids(self):
        return self.cache.keys()

    def get_network_by_id(self, network_id):
        return self.cache.get(network_id)

    def get_network_by_subnet_id(self, subnet_id):
        return self.cache.get(self.subnet_lookup.get(subnet_id))

    def get_network_by_port_id(self, port_id):
        return self.cache.get(self.port_lookup.get(port_id))

    def put(self, network):
        if network.id in self.cache:
            self.remove(self.cache[network.id])

        self.cache[network.id] = network

        for subnet in network.subnets:
            self.subnet_lookup[subnet.id] = network.id

        for port in network.ports:
            self.port_lookup[port.id] = network.id

    def remove(self, network):
        del self.cache[network.id]

        for subnet in network.subnets:
            del self.subnet_lookup[subnet.id]

        for port in network.ports:
            del self.port_lookup[port.id]

    def put_port(self, port):
        network = self.get_network_by_id(port.network_id)
        for index in range(len(network.ports)):
            if network.ports[index].id == port.id:
                network.ports[index] = port
                break
        else:
            network.ports.append(port)

        self.port_lookup[port.id] = network.id

    def remove_port(self, port):
        network = self.get_network_by_port_id(port.id)

        for index in range(len(network.ports)):
            if network.ports[index] == port:
                del network.ports[index]
                del self.port_lookup[port.id]
                break

    def get_port_by_id(self, port_id):
        network = self.get_network_by_port_id(port_id)
        if network:
            for port in network.ports:
                if port.id == port_id:
                    return port


class DeviceManager(object):
    OPTS = [
        cfg.StrOpt('admin_user'),
        cfg.StrOpt('admin_password'),
        cfg.StrOpt('admin_tenant_name'),
        cfg.StrOpt('auth_url'),
        cfg.StrOpt('auth_strategy', default='keystone'),
        cfg.StrOpt('auth_region'),
        cfg.StrOpt('interface_driver',
                   help="The driver used to manage the virtual interface.")
    ]

    def __init__(self, conf, plugin):
        self.conf = conf
        self.plugin = plugin
        if not conf.interface_driver:
            LOG.error(_('You must specify an interface driver'))
        self.driver = importutils.import_object(conf.interface_driver, conf)

    def get_interface_name(self, network, port=None):
        """Return interface(device) name for use by the DHCP process."""
        if not port:
            device_id = self.get_device_id(network)
            port = self.plugin.get_dhcp_port(network.id, device_id)
        return self.driver.get_device_name(port)

    def get_device_id(self, network):
        """Return a unique DHCP device ID for this host on the network."""
        # There could be more than one dhcp server per network, so create
        # a device id that combines host and network ids

        host_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname())
        return 'dhcp%s-%s' % (host_uuid, network.id)

    def setup(self, network, reuse_existing=False):
        """Create and initialize a device for network's DHCP on this host."""
        device_id = self.get_device_id(network)
        port = self.plugin.get_dhcp_port(network.id, device_id)

        interface_name = self.get_interface_name(network, port)

        if self.conf.use_namespaces:
            namespace = NS_PREFIX + network.id
        else:
            namespace = None

        if ip_lib.device_exists(interface_name,
                                self.conf.root_helper,
                                namespace):
            if not reuse_existing:
                raise exceptions.PreexistingDeviceFailure(
                    dev_name=interface_name)

            LOG.debug(_('Reusing existing device: %s.') % interface_name)
        else:
            self.driver.plug(network.id,
                             port.id,
                             interface_name,
                             port.mac_address,
                             namespace=namespace)
        ip_cidrs = []
        for fixed_ip in port.fixed_ips:
            subnet = fixed_ip.subnet
            net = netaddr.IPNetwork(subnet.cidr)
            ip_cidr = '%s/%s' % (fixed_ip.ip_address, net.prefixlen)
            ip_cidrs.append(ip_cidr)

        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=namespace)

        return interface_name

    def destroy(self, network, device_name):
        """Destroy the device used for the network's DHCP on this host."""
        if self.conf.use_namespaces:
            namespace = NS_PREFIX + network.id
        else:
            namespace = None

        self.driver.unplug(device_name, namespace=namespace)

        self.plugin.release_dhcp_port(network.id,
                                      self.get_device_id(network))


class DictModel(object):
    """Convert dict into an object that provides attribute access to values."""
    def __init__(self, d):
        for key, value in d.iteritems():
            if isinstance(value, list):
                value = [DictModel(item) if isinstance(item, dict) else item
                         for item in value]
            elif isinstance(value, dict):
                value = DictModel(value)

            setattr(self, key, value)


class DhcpLeaseRelay(object):
    """UNIX domain socket server for processing lease updates.

    Network namespace isolation prevents the DHCP process from notifying
    Quantum directly.  This class works around the limitation by using the
    domain socket to pass the information.  This class handles message.
    receiving and then calls the callback method.
    """

    OPTS = [
        cfg.StrOpt('dhcp_lease_relay_socket',
                   default='$state_path/dhcp/lease_relay',
                   help='Location to DHCP lease relay UNIX domain socket')
    ]

    def __init__(self, lease_update_callback):
        self.callback = lease_update_callback

        dirname = os.path.dirname(cfg.CONF.dhcp_lease_relay_socket)
        if os.path.isdir(dirname):
            try:
                os.unlink(cfg.CONF.dhcp_lease_relay_socket)
            except OSError:
                if os.path.exists(cfg.CONF.dhcp_lease_relay_socket):
                    raise
        else:
            os.makedirs(dirname, 0755)

    def _validate_field(self, value, regex):
        """Validate value against a regular expression and return if valid."""
        match = re.match(regex, value)

        if match:
            return value
        raise ValueError(_("Value %s does not match regex: %s") %
                         (value, regex))

    def _handler(self, client_sock, client_addr):
        """Handle incoming lease relay stream connection.

        This method will only read the first 1024 bytes and then close the
        connection.  The limit exists to limit the impact of misbehaving
        clients.
        """
        try:
            msg = client_sock.recv(1024)
            data = jsonutils.loads(msg)
            client_sock.close()

            network_id = self._validate_field(data['network_id'],
                                              attributes.UUID_PATTERN)
            ip_address = str(netaddr.IPAddress(data['ip_address']))
            lease_remaining = int(data['lease_remaining'])
            self.callback(network_id, ip_address, lease_remaining)
        except ValueError, e:
            LOG.warn(_('Unable to parse lease relay msg to dict.'))
            LOG.warn(_('Exception value: %s') % e)
            LOG.warn(_('Message representation: %s') % repr(msg))
        except Exception, e:
            LOG.exception(_('Unable update lease. Exception'))

    def start(self):
        """Spawn a green thread to run the lease relay unix socket server."""
        listener = eventlet.listen(cfg.CONF.dhcp_lease_relay_socket,
                                   family=socket.AF_UNIX)
        eventlet.spawn(eventlet.serve, listener, self._handler)


def main():
    eventlet.monkey_patch()
    cfg.CONF.register_opts(DhcpAgent.OPTS)
    cfg.CONF.register_opts(DeviceManager.OPTS)
    cfg.CONF.register_opts(DhcpLeaseRelay.OPTS)
    cfg.CONF.register_opts(dhcp.OPTS)
    cfg.CONF.register_opts(interface.OPTS)
    cfg.CONF(args=sys.argv, project='quantum')
    config.setup_logging(cfg.CONF)

    mgr = DhcpAgent(cfg.CONF)
    mgr.run()


if __name__ == '__main__':
    main()
