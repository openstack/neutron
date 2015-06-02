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

import collections
import os

import eventlet

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import importutils

from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.linux import utils as linux_utils
from neutron.agent.metadata import driver as metadata_driver
from neutron.agent import rpc as agent_rpc
from neutron.common import constants
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import context
from neutron.i18n import _LE, _LI, _LW
from neutron import manager
from neutron.openstack.common import loopingcall

LOG = logging.getLogger(__name__)


class DhcpAgent(manager.Manager):
    """DHCP agent service manager.

    Note that the public methods of this class are exposed as the server side
    of an rpc interface.  The neutron server uses
    neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.DhcpAgentNotifyApi as the
    client side to execute the methods here.  For more information about
    changing rpc interfaces, see doc/source/devref/rpc_api.rst.
    """
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, host=None):
        super(DhcpAgent, self).__init__(host=host)
        self.needs_resync_reasons = collections.defaultdict(list)
        self.conf = cfg.CONF
        self.cache = NetworkCache()
        self.dhcp_driver_cls = importutils.import_class(self.conf.dhcp_driver)
        ctx = context.get_admin_context_without_session()
        self.plugin_rpc = DhcpPluginApi(topics.PLUGIN,
                                        ctx, self.conf.use_namespaces)
        # create dhcp dir to store dhcp info
        dhcp_dir = os.path.dirname("/%s/dhcp/" % self.conf.state_path)
        linux_utils.ensure_dir(dhcp_dir)
        self.dhcp_version = self.dhcp_driver_cls.check_version()
        self._populate_networks_cache()
        self._process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='dhcp')

    def _populate_networks_cache(self):
        """Populate the networks cache when the DHCP-agent starts."""
        try:
            existing_networks = self.dhcp_driver_cls.existing_dhcp_networks(
                self.conf
            )
            for net_id in existing_networks:
                net = dhcp.NetModel(self.conf.use_namespaces,
                                    {"id": net_id,
                                     "subnets": [],
                                     "ports": []})
                self.cache.put(net)
        except NotImplementedError:
            # just go ahead with an empty networks cache
            LOG.debug("The '%s' DHCP-driver does not support retrieving of a "
                      "list of existing networks",
                      self.conf.dhcp_driver)

    def after_start(self):
        self.run()
        LOG.info(_LI("DHCP agent started"))

    def run(self):
        """Activate the DHCP agent."""
        self.sync_state()
        self.periodic_resync()

    def call_driver(self, action, network, **action_kwargs):
        """Invoke an action on a DHCP driver instance."""
        LOG.debug('Calling driver for network: %(net)s action: %(action)s',
                  {'net': network.id, 'action': action})
        try:
            # the Driver expects something that is duck typed similar to
            # the base models.
            driver = self.dhcp_driver_cls(self.conf,
                                          network,
                                          self._process_monitor,
                                          self.dhcp_version,
                                          self.plugin_rpc)
            getattr(driver, action)(**action_kwargs)
            return True
        except exceptions.Conflict:
            # No need to resync here, the agent will receive the event related
            # to a status update for the network
            LOG.warning(_LW('Unable to %(action)s dhcp for %(net_id)s: there '
                            'is a conflict with its current state; please '
                            'check that the network and/or its subnet(s) '
                            'still exist.'),
                        {'net_id': network.id, 'action': action})
        except Exception as e:
            if getattr(e, 'exc_type', '') != 'IpAddressGenerationFailure':
                # Don't resync if port could not be created because of an IP
                # allocation failure. When the subnet is updated with a new
                # allocation pool or a port is  deleted to free up an IP, this
                # will automatically be retried on the notification
                self.schedule_resync(e, network.id)
            if (isinstance(e, oslo_messaging.RemoteError)
                and e.exc_type == 'NetworkNotFound'
                or isinstance(e, exceptions.NetworkNotFound)):
                LOG.warning(_LW("Network %s has been deleted."), network.id)
            else:
                LOG.exception(_LE('Unable to %(action)s dhcp for %(net_id)s.'),
                              {'net_id': network.id, 'action': action})

    def schedule_resync(self, reason, network=None):
        """Schedule a resync for a given network and reason. If no network is
        specified, resync all networks.
        """
        self.needs_resync_reasons[network].append(reason)

    @utils.synchronized('dhcp-agent')
    def sync_state(self, networks=None):
        """Sync the local DHCP state with Neutron. If no networks are passed,
        or 'None' is one of the networks, sync all of the networks.
        """
        only_nets = set([] if (not networks or None in networks) else networks)
        LOG.info(_LI('Synchronizing state'))
        pool = eventlet.GreenPool(cfg.CONF.num_sync_threads)
        known_network_ids = set(self.cache.get_network_ids())

        try:
            active_networks = self.plugin_rpc.get_active_networks_info()
            active_network_ids = set(network.id for network in active_networks)
            for deleted_id in known_network_ids - active_network_ids:
                try:
                    self.disable_dhcp_helper(deleted_id)
                except Exception as e:
                    self.schedule_resync(e, deleted_id)
                    LOG.exception(_LE('Unable to sync network state on '
                                      'deleted network %s'), deleted_id)

            for network in active_networks:
                if (not only_nets or  # specifically resync all
                        network.id not in known_network_ids or  # missing net
                        network.id in only_nets):  # specific network to sync
                    pool.spawn(self.safe_configure_dhcp_for_network, network)
            pool.waitall()
            LOG.info(_LI('Synchronizing state complete'))

        except Exception as e:
            self.schedule_resync(e)
            LOG.exception(_LE('Unable to sync network state.'))

    @utils.exception_logger()
    def _periodic_resync_helper(self):
        """Resync the dhcp state at the configured interval."""
        while True:
            eventlet.sleep(self.conf.resync_interval)
            if self.needs_resync_reasons:
                # be careful to avoid a race with additions to list
                # from other threads
                reasons = self.needs_resync_reasons
                self.needs_resync_reasons = collections.defaultdict(list)
                for net, r in reasons.items():
                    if not net:
                        net = "*"
                    LOG.debug("resync (%(network)s): %(reason)s",
                              {"reason": r, "network": net})
                self.sync_state(reasons.keys())

    def periodic_resync(self):
        """Spawn a thread to periodically resync the dhcp state."""
        eventlet.spawn(self._periodic_resync_helper)

    def safe_get_network_info(self, network_id):
        try:
            network = self.plugin_rpc.get_network_info(network_id)
            if not network:
                LOG.warn(_LW('Network %s has been deleted.'), network_id)
            return network
        except Exception as e:
            self.schedule_resync(e, network_id)
            LOG.exception(_LE('Network %s info call failed.'), network_id)

    def enable_dhcp_helper(self, network_id):
        """Enable DHCP for a network that meets enabling criteria."""
        network = self.safe_get_network_info(network_id)
        if network:
            self.configure_dhcp_for_network(network)

    @utils.exception_logger()
    def safe_configure_dhcp_for_network(self, network):
        try:
            self.configure_dhcp_for_network(network)
        except (exceptions.NetworkNotFound, RuntimeError):
            LOG.warn(_LW('Network %s may have been deleted and its resources '
                         'may have already been disposed.'), network.id)

    def configure_dhcp_for_network(self, network):
        if not network.admin_state_up:
            return

        enable_metadata = self.dhcp_driver_cls.should_enable_metadata(
                self.conf, network)
        dhcp_network_enabled = False

        for subnet in network.subnets:
            if subnet.enable_dhcp:
                if self.call_driver('enable', network):
                    dhcp_network_enabled = True
                    self.cache.put(network)
                break

        if enable_metadata and dhcp_network_enabled:
            for subnet in network.subnets:
                if subnet.ip_version == 4 and subnet.enable_dhcp:
                    self.enable_isolated_metadata_proxy(network)
                    break

    def disable_dhcp_helper(self, network_id):
        """Disable DHCP for a network known to the agent."""
        network = self.cache.get_network_by_id(network_id)
        if network:
            if (self.conf.use_namespaces and
                self.conf.enable_isolated_metadata):
                # NOTE(jschwarz): In the case where a network is deleted, all
                # the subnets and ports are deleted before this function is
                # called, so checking if 'should_enable_metadata' is True
                # for any subnet is false logic here.
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

        network = self.safe_get_network_info(network_id)
        if not network:
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

    @utils.synchronized('dhcp-agent')
    def network_create_end(self, context, payload):
        """Handle the network.create.end notification event."""
        network_id = payload['network']['id']
        self.enable_dhcp_helper(network_id)

    @utils.synchronized('dhcp-agent')
    def network_update_end(self, context, payload):
        """Handle the network.update.end notification event."""
        network_id = payload['network']['id']
        if payload['network']['admin_state_up']:
            self.enable_dhcp_helper(network_id)
        else:
            self.disable_dhcp_helper(network_id)

    @utils.synchronized('dhcp-agent')
    def network_delete_end(self, context, payload):
        """Handle the network.delete.end notification event."""
        self.disable_dhcp_helper(payload['network_id'])

    @utils.synchronized('dhcp-agent')
    def subnet_update_end(self, context, payload):
        """Handle the subnet.update.end notification event."""
        network_id = payload['subnet']['network_id']
        self.refresh_dhcp_helper(network_id)

    # Use the update handler for the subnet create event.
    subnet_create_end = subnet_update_end

    @utils.synchronized('dhcp-agent')
    def subnet_delete_end(self, context, payload):
        """Handle the subnet.delete.end notification event."""
        subnet_id = payload['subnet_id']
        network = self.cache.get_network_by_subnet_id(subnet_id)
        if network:
            self.refresh_dhcp_helper(network.id)

    @utils.synchronized('dhcp-agent')
    def port_update_end(self, context, payload):
        """Handle the port.update.end notification event."""
        updated_port = dhcp.DictModel(payload['port'])
        network = self.cache.get_network_by_id(updated_port.network_id)
        if network:
            driver_action = 'reload_allocations'
            if self._is_port_on_this_agent(updated_port):
                orig = self.cache.get_port_by_id(updated_port['id'])
                # assume IP change if not in cache
                old_ips = {i['ip_address'] for i in orig['fixed_ips'] or []}
                new_ips = {i['ip_address'] for i in updated_port['fixed_ips']}
                if old_ips != new_ips:
                    driver_action = 'restart'
            self.cache.put_port(updated_port)
            self.call_driver(driver_action, network)

    def _is_port_on_this_agent(self, port):
        thishost = utils.get_dhcp_agent_device_id(
            port['network_id'], self.conf.host)
        return port['device_id'] == thishost

    # Use the update handler for the port create event.
    port_create_end = port_update_end

    @utils.synchronized('dhcp-agent')
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
        kwargs = {'network_id': network.id}
        # When the metadata network is enabled, the proxy might
        # be started for the router attached to the network
        if self.conf.enable_metadata_network:
            router_ports = [port for port in network.ports
                            if (port.device_owner in
                                constants.ROUTER_INTERFACE_OWNERS)]
            if router_ports:
                # Multiple router ports should not be allowed
                if len(router_ports) > 1:
                    LOG.warning(_LW("%(port_num)d router ports found on the "
                                    "metadata access network. Only the port "
                                    "%(port_id)s, for router %(router_id)s "
                                    "will be considered"),
                                {'port_num': len(router_ports),
                                 'port_id': router_ports[0].id,
                                 'router_id': router_ports[0].device_id})
                kwargs = {'router_id': router_ports[0].device_id}

        metadata_driver.MetadataDriver.spawn_monitored_metadata_proxy(
            self._process_monitor, network.namespace, dhcp.METADATA_PORT,
            self.conf, **kwargs)

    def disable_isolated_metadata_proxy(self, network):
        metadata_driver.MetadataDriver.destroy_monitored_metadata_proxy(
            self._process_monitor, network.id, self.conf)


class DhcpPluginApi(object):
    """Agent side of the dhcp rpc API.

    This class implements the client side of an rpc interface.  The server side
    of this interface can be found in
    neutron.api.rpc.handlers.dhcp_rpc.DhcpRpcCallback.  For more information
    about changing rpc interfaces, see doc/source/devref/rpc_api.rst.

    API version history:
        1.0 - Initial version.
        1.1 - Added get_active_networks_info, create_dhcp_port,
              and update_dhcp_port methods.

    """

    def __init__(self, topic, context, use_namespaces):
        self.context = context
        self.host = cfg.CONF.host
        self.use_namespaces = use_namespaces
        target = oslo_messaging.Target(
                topic=topic,
                namespace=constants.RPC_NAMESPACE_DHCP_PLUGIN,
                version='1.0')
        self.client = n_rpc.get_client(target)

    def get_active_networks_info(self):
        """Make a remote process call to retrieve all network info."""
        cctxt = self.client.prepare(version='1.1')
        networks = cctxt.call(self.context, 'get_active_networks_info',
                              host=self.host)
        return [dhcp.NetModel(self.use_namespaces, n) for n in networks]

    def get_network_info(self, network_id):
        """Make a remote process call to retrieve network info."""
        cctxt = self.client.prepare()
        network = cctxt.call(self.context, 'get_network_info',
                             network_id=network_id, host=self.host)
        if network:
            return dhcp.NetModel(self.use_namespaces, network)

    def create_dhcp_port(self, port):
        """Make a remote process call to create the dhcp port."""
        cctxt = self.client.prepare(version='1.1')
        port = cctxt.call(self.context, 'create_dhcp_port',
                          port=port, host=self.host)
        if port:
            return dhcp.DictModel(port)

    def update_dhcp_port(self, port_id, port):
        """Make a remote process call to update the dhcp port."""
        cctxt = self.client.prepare(version='1.1')
        port = cctxt.call(self.context, 'update_dhcp_port',
                          port_id=port_id, port=port, host=self.host)
        if port:
            return dhcp.DictModel(port)

    def release_dhcp_port(self, network_id, device_id):
        """Make a remote process call to release the dhcp port."""
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'release_dhcp_port',
                          network_id=network_id, device_id=device_id,
                          host=self.host)

    def release_port_fixed_ip(self, network_id, device_id, subnet_id):
        """Make a remote process call to release a fixed_ip on the port."""
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'release_port_fixed_ip',
                          network_id=network_id, subnet_id=subnet_id,
                          device_id=device_id, host=self.host)


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


class DhcpAgentWithStateReport(DhcpAgent):
    def __init__(self, host=None):
        super(DhcpAgentWithStateReport, self).__init__(host=host)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-dhcp-agent',
            'host': host,
            'topic': topics.DHCP_AGENT,
            'configurations': {
                'dhcp_driver': cfg.CONF.dhcp_driver,
                'use_namespaces': cfg.CONF.use_namespaces,
                'dhcp_lease_duration': cfg.CONF.dhcp_lease_duration},
            'start_flag': True,
            'agent_type': constants.AGENT_TYPE_DHCP}
        report_interval = cfg.CONF.AGENT.report_interval
        self.use_call = True
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self.agent_state.get('configurations').update(
                self.cache.get_state())
            ctx = context.get_admin_context_without_session()
            self.state_rpc.report_state(ctx, self.agent_state, self.use_call)
            self.use_call = False
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_LW("Neutron server does not support state report."
                         " State report for this agent will be disabled."))
            self.heartbeat.stop()
            self.run()
            return
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))
            return
        if self.agent_state.pop('start_flag', None):
            self.run()

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.schedule_resync(_("Agent updated: %(payload)s") %
                             {"payload": payload})
        LOG.info(_LI("agent_updated by server side %s!"), payload)

    def after_start(self):
        LOG.info(_LI("DHCP agent started"))
