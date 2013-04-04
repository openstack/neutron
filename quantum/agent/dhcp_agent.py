# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

import os
import socket
import uuid

import eventlet
import netaddr
from oslo.config import cfg

from quantum.agent.common import config
from quantum.agent.linux import dhcp
from quantum.agent.linux import external_process
from quantum.agent.linux import interface
from quantum.agent.linux import ip_lib
from quantum.agent import rpc as agent_rpc
from quantum.common import constants
from quantum.common import exceptions
from quantum.common import topics
from quantum import context
from quantum import manager
from quantum.openstack.common import importutils
from quantum.openstack.common import jsonutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import lockutils
from quantum.openstack.common import loopingcall
from quantum.openstack.common.rpc import proxy
from quantum.openstack.common import service
from quantum.openstack.common import uuidutils
from quantum import service as quantum_service

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qdhcp-'
METADATA_DEFAULT_PREFIX = 16
METADATA_DEFAULT_IP = '169.254.169.254/%d' % METADATA_DEFAULT_PREFIX
METADATA_PORT = 80


class DhcpAgent(manager.Manager):
    OPTS = [
        cfg.IntOpt('resync_interval', default=5,
                   help=_("Interval to resync.")),
        cfg.StrOpt('dhcp_driver',
                   default='quantum.agent.linux.dhcp.Dnsmasq',
                   help=_("The driver used to manage the DHCP server.")),
        cfg.BoolOpt('use_namespaces', default=True,
                    help=_("Allow overlapping IP.")),
        cfg.BoolOpt('enable_isolated_metadata', default=False,
                    help=_("Support Metadata requests on isolated networks.")),
        cfg.BoolOpt('enable_metadata_network', default=False,
                    help=_("Allows for serving metadata requests from a "
                           "dedicate network. Requires "
                           "enable isolated_metadata = True ")),
    ]

    def __init__(self, host=None):
        super(DhcpAgent, self).__init__(host=host)
        self.needs_resync = False
        self.conf = cfg.CONF
        self.cache = NetworkCache()
        self.root_helper = config.get_root_helper(self.conf)
        self.dhcp_driver_cls = importutils.import_class(self.conf.dhcp_driver)
        ctx = context.get_admin_context_without_session()
        self.plugin_rpc = DhcpPluginApi(topics.PLUGIN, ctx)
        self.device_manager = DeviceManager(self.conf, self.plugin_rpc)
        self.lease_relay = DhcpLeaseRelay(self.update_lease)

        self._populate_networks_cache()

    def _populate_networks_cache(self):
        """Populate the networks cache when the DHCP-agent starts"""

        try:
            existing_networks = self.dhcp_driver_cls.existing_dhcp_networks(
                self.conf,
                self.root_helper
            )

            for net_id in existing_networks:
                net = DictModel({"id": net_id, "subnets": [], "ports": []})
                self.cache.put(net)
        except NotImplementedError:
            # just go ahead with an empty networks cache
            LOG.debug(
                _("The '%s' DHCP-driver does not support retrieving of a "
                  "list of existing networks"),
                self.conf.dhcp_driver
            )

    def after_start(self):
        self.run()
        LOG.info(_("DHCP agent started"))

    def run(self):
        """Activate the DHCP agent."""
        self.sync_state()
        self.periodic_resync()
        self.lease_relay.start()

    def _ns_name(self, network):
        if self.conf.use_namespaces:
            return NS_PREFIX + network.id

    def call_driver(self, action, network):
        """Invoke an action on a DHCP driver instance."""
        try:
            # the Driver expects something that is duck typed similar to
            # the base models.
            driver = self.dhcp_driver_cls(self.conf,
                                          network,
                                          self.root_helper,
                                          self.device_manager,
                                          self._ns_name(network))
            getattr(driver, action)()
            return True

        except Exception:
            self.needs_resync = True
            LOG.exception(_('Unable to %s dhcp.'), action)

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
            LOG.exception(_('Network %s RPC info call failed.'), network_id)
            return

        if not network.admin_state_up:
            return

        for subnet in network.subnets:
            if subnet.enable_dhcp:
                if self.call_driver('enable', network):
                    if self.conf.use_namespaces:
                        self.enable_isolated_metadata_proxy(network)
                    self.cache.put(network)
                break

    def disable_dhcp_helper(self, network_id):
        """Disable DHCP for a network known to the agent."""
        network = self.cache.get_network_by_id(network_id)
        if network:
            if self.conf.use_namespaces:
                self.disable_isolated_metadata_proxy(network)
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
            LOG.exception(_('Network %s RPC info call failed.'), network_id)
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

    @lockutils.synchronized('agent', 'dhcp-')
    def network_create_end(self, context, payload):
        """Handle the network.create.end notification event."""
        network_id = payload['network']['id']
        self.enable_dhcp_helper(network_id)

    @lockutils.synchronized('agent', 'dhcp-')
    def network_update_end(self, context, payload):
        """Handle the network.update.end notification event."""
        network_id = payload['network']['id']
        if payload['network']['admin_state_up']:
            self.enable_dhcp_helper(network_id)
        else:
            self.disable_dhcp_helper(network_id)

    @lockutils.synchronized('agent', 'dhcp-')
    def network_delete_end(self, context, payload):
        """Handle the network.delete.end notification event."""
        self.disable_dhcp_helper(payload['network_id'])

    @lockutils.synchronized('agent', 'dhcp-')
    def subnet_update_end(self, context, payload):
        """Handle the subnet.update.end notification event."""
        network_id = payload['subnet']['network_id']
        self.refresh_dhcp_helper(network_id)

    # Use the update handler for the subnet create event.
    subnet_create_end = subnet_update_end

    @lockutils.synchronized('agent', 'dhcp-')
    def subnet_delete_end(self, context, payload):
        """Handle the subnet.delete.end notification event."""
        subnet_id = payload['subnet_id']
        network = self.cache.get_network_by_subnet_id(subnet_id)
        if network:
            self.refresh_dhcp_helper(network.id)

    @lockutils.synchronized('agent', 'dhcp-')
    def port_update_end(self, context, payload):
        """Handle the port.update.end notification event."""
        port = DictModel(payload['port'])
        network = self.cache.get_network_by_id(port.network_id)
        if network:
            self.cache.put_port(port)
            self.call_driver('reload_allocations', network)

    # Use the update handler for the port create event.
    port_create_end = port_update_end

    @lockutils.synchronized('agent', 'dhcp-')
    def port_delete_end(self, context, payload):
        """Handle the port.delete.end notification event."""
        port = self.cache.get_port_by_id(payload['port_id'])
        if port:
            network = self.cache.get_network_by_id(port.network_id)
            self.cache.remove_port(port)
            self.call_driver('reload_allocations', network)

    def enable_isolated_metadata_proxy(self, network):

        # The proxy might work for either a single network
        # or all the networks connected via a router
        # to the one passed as a parameter
        quantum_lookup_param = '--network_id=%s' % network.id
        meta_cidr = netaddr.IPNetwork(METADATA_DEFAULT_IP)
        has_metadata_subnet = any(netaddr.IPNetwork(s.cidr) in meta_cidr
                                  for s in network.subnets)
        if (self.conf.enable_metadata_network and has_metadata_subnet):
            router_ports = [port for port in network.ports
                            if (port.device_owner ==
                                constants.DEVICE_OWNER_ROUTER_INTF)]
            if router_ports:
                # Multiple router ports should not be allowed
                if len(router_ports) > 1:
                    LOG.warning(_("%(port_num)d router ports found on the "
                                  "metadata access network. Only the port "
                                  "%(port_id)s, for router %(router_id)s "
                                  "will be considered"),
                                {'port_num': len(router_ports),
                                 'port_id': router_ports[0].id,
                                 'router_id': router_ports[0].device_id})
                quantum_lookup_param = ('--router_id=%s' %
                                        router_ports[0].device_id)

        def callback(pid_file):
            proxy_cmd = ['quantum-ns-metadata-proxy',
                         '--pid_file=%s' % pid_file,
                         quantum_lookup_param,
                         '--state_path=%s' % self.conf.state_path,
                         '--metadata_port=%d' % METADATA_PORT]
            proxy_cmd.extend(config.get_log_args(
                cfg.CONF, 'quantum-ns-metadata-proxy-%s.log' % network.id))
            return proxy_cmd

        pm = external_process.ProcessManager(
            self.conf,
            network.id,
            self.conf.root_helper,
            self._ns_name(network))
        pm.enable(callback)

    def disable_isolated_metadata_proxy(self, network):
        pm = external_process.ProcessManager(
            self.conf,
            network.id,
            self.conf.root_helper,
            self._ns_name(network))
        pm.disable()


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
        self.host = cfg.CONF.host

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

    def get_state(self):
        net_ids = self.get_network_ids()
        num_nets = len(net_ids)
        num_subnets = 0
        num_ports = 0
        for net_id in net_ids:
            network = self.get_network_by_id(net_id)
            num_subnets += len(network.subnets)
            num_ports += len(network.ports)
        return {'networks': num_nets,
                'subnets': num_subnets,
                'ports': num_ports}


class DeviceManager(object):
    OPTS = [
        cfg.StrOpt('interface_driver',
                   help=_("The driver used to manage the virtual interface."))
    ]

    def __init__(self, conf, plugin):
        self.conf = conf
        self.root_helper = config.get_root_helper(conf)
        self.plugin = plugin
        if not conf.interface_driver:
            raise SystemExit(_('You must specify an interface driver'))
        try:
            self.driver = importutils.import_object(conf.interface_driver,
                                                    conf)
        except:
            msg = _("Error importing interface driver "
                    "'%s'") % conf.interface_driver
            raise SystemExit(msg)

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
                                self.root_helper,
                                namespace):
            if not reuse_existing:
                raise exceptions.PreexistingDeviceFailure(
                    dev_name=interface_name)

            LOG.debug(_('Reusing existing device: %s.'), interface_name)
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

        if (self.conf.enable_isolated_metadata and
            self.conf.use_namespaces):
            ip_cidrs.append(METADATA_DEFAULT_IP)

        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=namespace)

        # ensure that the dhcp interface is first in the list
        if namespace is None:
            device = ip_lib.IPDevice(interface_name,
                                     self.root_helper)
            device.route.pullup_route(interface_name)

        if self.conf.enable_metadata_network:
            meta_cidr = netaddr.IPNetwork(METADATA_DEFAULT_IP)
            metadata_subnets = [s for s in network.subnets if
                                netaddr.IPNetwork(s.cidr) in meta_cidr]
            if metadata_subnets:
                # Add a gateway so that packets can be routed back to VMs
                device = ip_lib.IPDevice(interface_name,
                                         self.root_helper,
                                         namespace)
                # Only 1 subnet on metadata access network
                gateway_ip = metadata_subnets[0].gateway_ip
                device.route.add_gateway(gateway_ip)

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
                   help=_('Location to DHCP lease relay UNIX domain socket'))
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

            network_id = data['network_id']
            if not uuidutils.is_uuid_like(network_id):
                raise ValueError(_("Network ID %s is not a valid UUID") %
                                 network_id)
            ip_address = str(netaddr.IPAddress(data['ip_address']))
            lease_remaining = int(data['lease_remaining'])
            self.callback(network_id, ip_address, lease_remaining)
        except ValueError, e:
            LOG.warn(_('Unable to parse lease relay msg to dict.'))
            LOG.warn(_('Exception value: %s'), e)
            LOG.warn(_('Message representation: %s'), repr(msg))
        except Exception, e:
            LOG.exception(_('Unable update lease. Exception'))

    def start(self):
        """Spawn a green thread to run the lease relay unix socket server."""
        listener = eventlet.listen(cfg.CONF.dhcp_lease_relay_socket,
                                   family=socket.AF_UNIX)
        eventlet.spawn(eventlet.serve, listener, self._handler)


class DhcpAgentWithStateReport(DhcpAgent):
    def __init__(self, host=None):
        super(DhcpAgentWithStateReport, self).__init__(host=host)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'quantum-dhcp-agent',
            'host': host,
            'topic': topics.DHCP_AGENT,
            'configurations': {
                'dhcp_driver': cfg.CONF.dhcp_driver,
                'use_namespaces': cfg.CONF.use_namespaces,
                'dhcp_lease_time': cfg.CONF.dhcp_lease_time},
            'start_flag': True,
            'agent_type': constants.AGENT_TYPE_DHCP}
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.LoopingCall(self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self.agent_state.get('configurations').update(
                self.cache.get_state())
            ctx = context.get_admin_context_without_session()
            self.state_rpc.report_state(ctx,
                                        self.agent_state)
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Quantum server does not support state report."
                       " State report for this agent will be disabled."))
            self.heartbeat.stop()
            self.run()
            return
        except Exception:
            LOG.exception(_("Failed reporting state!"))
            return
        if self.agent_state.pop('start_flag', None):
            self.run()

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.needs_resync = True
        LOG.info(_("agent_updated by server side %s!"), payload)

    def after_start(self):
        LOG.info(_("DHCP agent started"))


def register_options():
    cfg.CONF.register_opts(DhcpAgent.OPTS)
    config.register_agent_state_opts_helper(cfg.CONF)
    config.register_root_helper(cfg.CONF)
    cfg.CONF.register_opts(DeviceManager.OPTS)
    cfg.CONF.register_opts(DhcpLeaseRelay.OPTS)
    cfg.CONF.register_opts(dhcp.OPTS)
    cfg.CONF.register_opts(interface.OPTS)


def main():
    eventlet.monkey_patch()
    register_options()
    cfg.CONF(project='quantum')
    config.setup_logging(cfg.CONF)
    server = quantum_service.Service.create(
        binary='quantum-dhcp-agent',
        topic=topics.DHCP_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='quantum.agent.dhcp_agent.DhcpAgentWithStateReport')
    service.launch(server).wait()
