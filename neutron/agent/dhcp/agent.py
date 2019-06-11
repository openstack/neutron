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
from neutron_lib.agent import constants as agent_consts
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_utils import fileutils
from oslo_utils import importutils
import six

from neutron._i18n import _
from neutron.agent.common import resource_processing_queue as queue
from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.metadata import driver as metadata_driver
from neutron.agent import rpc as agent_rpc
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import manager

LOG = logging.getLogger(__name__)
_SYNC_STATE_LOCK = lockutils.ReaderWriterLock()

DEFAULT_PRIORITY = 255


def _sync_lock(f):
    """Decorator to block all operations for a global sync call."""
    @six.wraps(f)
    def wrapped(*args, **kwargs):
        with _SYNC_STATE_LOCK.write_lock():
            return f(*args, **kwargs)
    return wrapped


def _wait_if_syncing(f):
    """Decorator to wait if any sync operations are in progress."""
    @six.wraps(f)
    def wrapped(*args, **kwargs):
        with _SYNC_STATE_LOCK.read_lock():
            return f(*args, **kwargs)
    return wrapped


class DhcpAgent(manager.Manager):
    """DHCP agent service manager.

    Note that the public methods of this class are exposed as the server side
    of an rpc interface.  The neutron server uses
    neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.DhcpAgentNotifyApi as the
    client side to execute the methods here.  For more information about
    changing rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, host=None, conf=None):
        super(DhcpAgent, self).__init__(host=host)
        self.needs_resync_reasons = collections.defaultdict(list)
        self.dhcp_ready_ports = set()
        self.conf = conf or cfg.CONF
        self.cache = NetworkCache()
        self.dhcp_driver_cls = importutils.import_class(self.conf.dhcp_driver)
        self.plugin_rpc = DhcpPluginApi(topics.PLUGIN, self.conf.host)
        # create dhcp dir to store dhcp info
        dhcp_dir = os.path.dirname("/%s/dhcp/" % self.conf.state_path)
        fileutils.ensure_tree(dhcp_dir, mode=0o755)
        self.dhcp_version = self.dhcp_driver_cls.check_version()
        self._populate_networks_cache()
        # keep track of mappings between networks and routers for
        # metadata processing
        self._metadata_routers = {}  # {network_id: router_id}
        self._process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='dhcp')
        self._queue = queue.ResourceProcessingQueue()

    def init_host(self):
        self.sync_state()

    def _populate_networks_cache(self):
        """Populate the networks cache when the DHCP-agent starts."""
        try:
            existing_networks = self.dhcp_driver_cls.existing_dhcp_networks(
                self.conf
            )
            for net_id in existing_networks:
                net = dhcp.NetModel({"id": net_id, "subnets": [],
                                     "non_local_subnets": [], "ports": []})
                self.cache.put(net)
        except NotImplementedError:
            # just go ahead with an empty networks cache
            LOG.debug("The '%s' DHCP-driver does not support retrieving of a "
                      "list of existing networks",
                      self.conf.dhcp_driver)

    def after_start(self):
        self.run()
        LOG.info("DHCP agent started")

    def run(self):
        """Activate the DHCP agent."""
        self.periodic_resync()
        self.start_ready_ports_loop()
        eventlet.spawn_n(self._process_loop)

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
            LOG.debug('Unable to %(action)s dhcp for %(net_id)s: there '
                      'is a conflict with its current state; please '
                      'check that the network and/or its subnet(s) '
                      'still exist.', {'net_id': network.id, 'action': action})
        except exceptions.SubnetMismatchForPort as e:
            # FIXME(kevinbenton): get rid of this once bug/1627480 is fixed
            LOG.debug("Error configuring DHCP port, scheduling resync: %s", e)
            self.schedule_resync(e, network.id)
        except Exception as e:
            if getattr(e, 'exc_type', '') != 'IpAddressGenerationFailure':
                # Don't resync if port could not be created because of an IP
                # allocation failure. When the subnet is updated with a new
                # allocation pool or a port is  deleted to free up an IP, this
                # will automatically be retried on the notification
                self.schedule_resync(e, network.id)
            if (isinstance(e, oslo_messaging.RemoteError) and
                    e.exc_type == 'NetworkNotFound' or
                    isinstance(e, exceptions.NetworkNotFound)):
                LOG.debug("Network %s has been removed from the agent "
                          "or deleted from DB.", network.id)
            else:
                LOG.exception('Unable to %(action)s dhcp for %(net_id)s.',
                              {'net_id': network.id, 'action': action})

    def schedule_resync(self, reason, network_id=None):
        """Schedule a resync for a given network and reason. If no network is
        specified, resync all networks.
        """
        self.needs_resync_reasons[network_id].append(reason)

    @_sync_lock
    def sync_state(self, networks=None):
        """Sync the local DHCP state with Neutron. If no networks are passed,
        or 'None' is one of the networks, sync all of the networks.
        """
        only_nets = set([] if (not networks or None in networks) else networks)
        LOG.info('Synchronizing state')
        pool = eventlet.GreenPool(self.conf.num_sync_threads)
        known_network_ids = set(self.cache.get_network_ids())

        try:
            active_networks = self.plugin_rpc.get_active_networks_info(
                enable_dhcp_filter=False)
            LOG.info('All active networks have been fetched through RPC.')
            active_network_ids = set(network.id for network in active_networks)
            for deleted_id in known_network_ids - active_network_ids:
                try:
                    self.disable_dhcp_helper(deleted_id)
                except Exception as e:
                    self.schedule_resync(e, deleted_id)
                    LOG.exception('Unable to sync network state on '
                                  'deleted network %s', deleted_id)

            for network in active_networks:
                if (not only_nets or  # specifically resync all
                        network.id not in known_network_ids or  # missing net
                        network.id in only_nets):  # specific network to sync
                    pool.spawn(self.safe_configure_dhcp_for_network, network)
            pool.waitall()
            # we notify all ports in case some were created while the agent
            # was down
            self.dhcp_ready_ports |= set(self.cache.get_port_ids(only_nets))
            LOG.info('Synchronizing state complete')

        except Exception as e:
            if only_nets:
                for network_id in only_nets:
                    self.schedule_resync(e, network_id)
            else:
                self.schedule_resync(e)
            LOG.exception('Unable to sync network state.')

    def _dhcp_ready_ports_loop(self):
        """Notifies the server of any ports that had reservations setup."""
        while True:
            # this is just watching a set so we can do it really frequently
            eventlet.sleep(0.1)
            if self.dhcp_ready_ports:
                ports_to_send = self.dhcp_ready_ports
                self.dhcp_ready_ports = set()
                try:
                    self.plugin_rpc.dhcp_ready_on_ports(ports_to_send)
                    continue
                except oslo_messaging.MessagingTimeout:
                    LOG.error("Timeout notifying server of ports ready. "
                              "Retrying...")
                except Exception:
                    LOG.exception("Failure notifying DHCP server of "
                                  "ready DHCP ports. Will retry on next "
                                  "iteration.")
                self.dhcp_ready_ports |= ports_to_send

    def start_ready_ports_loop(self):
        """Spawn a thread to push changed ports to server."""
        eventlet.spawn(self._dhcp_ready_ports_loop)

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
                LOG.debug('Network %s has been deleted.', network_id)
            return network
        except Exception as e:
            self.schedule_resync(e, network_id)
            LOG.exception('Network %s info call failed.', network_id)

    def enable_dhcp_helper(self, network_id):
        """Enable DHCP for a network that meets enabling criteria."""
        network = self.safe_get_network_info(network_id)
        if network:
            self.configure_dhcp_for_network(network)

    @utils.exception_logger()
    def safe_configure_dhcp_for_network(self, network):
        try:
            network_id = network.get('id')
            LOG.info('Starting network %s dhcp configuration', network_id)
            self.configure_dhcp_for_network(network)
            LOG.info('Finished network %s dhcp configuration', network_id)
        except (exceptions.NetworkNotFound, RuntimeError):
            LOG.warning('Network %s may have been deleted and '
                        'its resources may have already been disposed.',
                        network.id)

    def configure_dhcp_for_network(self, network):
        if not network.admin_state_up:
            return

        for subnet in network.subnets:
            if subnet.enable_dhcp:
                if self.call_driver('enable', network):
                    self.update_isolated_metadata_proxy(network)
                    self.cache.put(network)
                    # After enabling dhcp for network, mark all existing
                    # ports as ready. So that the status of ports which are
                    # created before enabling dhcp can be updated.
                    self.dhcp_ready_ports |= {p.id for p in network.ports}
                break

    def disable_dhcp_helper(self, network_id):
        """Disable DHCP for a network known to the agent."""
        network = self.cache.get_network_by_id(network_id)
        if network:
            # NOTE(yamahata): Kill the metadata proxy process
            # unconditionally, as in the case where a network
            # is deleted, all the subnets and ports are deleted
            # before this function is called, so determining if
            # the proxy should be terminated is error prone.
            # destroy_monitored_metadata_proxy() is a noop when
            # there is no process running.
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

        if not any(s for s in network.subnets if s.enable_dhcp):
            self.disable_dhcp_helper(network.id)
            return
        old_non_local_subnets = getattr(old_network, 'non_local_subnets', [])
        new_non_local_subnets = getattr(network, 'non_local_subnets', [])
        old_cidrs = [s.cidr for s in (old_network.subnets +
                                      old_non_local_subnets) if s.enable_dhcp]
        new_cidrs = [s.cidr for s in (network.subnets +
                                      new_non_local_subnets) if s.enable_dhcp]
        if old_cidrs == new_cidrs:
            self.call_driver('reload_allocations', network)
            self.cache.put(network)
        elif self.call_driver('restart', network):
            self.cache.put(network)
        # mark all ports as active in case the sync included
        # new ports that we hadn't seen yet.
        self.dhcp_ready_ports |= {p.id for p in network.ports}

        # Update the metadata proxy after the dhcp driver has been updated
        self.update_isolated_metadata_proxy(network)

    def network_create_end(self, context, payload):
        """Handle the network.create.end notification event."""
        update = queue.ResourceUpdate(payload['network']['id'],
                                      payload.get('priority',
                                                  DEFAULT_PRIORITY),
                                      action='_network_create',
                                      resource=payload)
        self._queue.add(update)

    @_wait_if_syncing
    def _network_create(self, payload):
        network_id = payload['network']['id']
        self.enable_dhcp_helper(network_id)

    def network_update_end(self, context, payload):
        """Handle the network.update.end notification event."""
        update = queue.ResourceUpdate(payload['network']['id'],
                                      payload.get('priority',
                                                  DEFAULT_PRIORITY),
                                      action='_network_update',
                                      resource=payload)
        self._queue.add(update)

    @_wait_if_syncing
    def _network_update(self, payload):
        network_id = payload['network']['id']
        if payload['network']['admin_state_up']:
            self.enable_dhcp_helper(network_id)
        else:
            self.disable_dhcp_helper(network_id)

    def network_delete_end(self, context, payload):
        """Handle the network.delete.end notification event."""
        update = queue.ResourceUpdate(payload['network_id'],
                                      payload.get('priority',
                                                  DEFAULT_PRIORITY),
                                      action='_network_delete',
                                      resource=payload)
        self._queue.add(update)

    @_wait_if_syncing
    def _network_delete(self, payload):
        network_id = payload['network_id']
        self.disable_dhcp_helper(network_id)

    def subnet_update_end(self, context, payload):
        """Handle the subnet.update.end notification event."""
        update = queue.ResourceUpdate(payload['subnet']['network_id'],
                                      payload.get('priority',
                                                  DEFAULT_PRIORITY),
                                      action='_subnet_update',
                                      resource=payload)
        self._queue.add(update)

    @_wait_if_syncing
    def _subnet_update(self, payload):
        network_id = payload['subnet']['network_id']
        self.refresh_dhcp_helper(network_id)

    # Use the update handler for the subnet create event.
    subnet_create_end = subnet_update_end

    def _get_network_lock_id(self, payload):
        """Determine which lock to hold when servicing an RPC event"""
        # TODO(alegacy): in a future release this function can be removed and
        # uses of it can be replaced with payload['network_id'].  It exists
        # only to satisfy backwards compatibility between older servers and
        # newer agents.  Once the 'network_id' attribute is guaranteed to be
        # sent by the server on all *_delete_end events then it can be removed.
        if 'network_id' in payload:
            return payload['network_id']
        elif 'subnet_id' in payload:
            subnet_id = payload['subnet_id']
            network = self.cache.get_network_by_subnet_id(subnet_id)
            return network.id if network else None
        elif 'port_id' in payload:
            port_id = payload['port_id']
            port = self.cache.get_port_by_id(port_id)
            return port.network_id if port else None

    def subnet_delete_end(self, context, payload):
        """Handle the subnet.delete.end notification event."""
        network_id = self._get_network_lock_id(payload)
        if not network_id:
            return
        update = queue.ResourceUpdate(network_id,
                                      payload.get('priority',
                                                  DEFAULT_PRIORITY),
                                      action='_subnet_delete',
                                      resource=payload)
        self._queue.add(update)

    @_wait_if_syncing
    def _subnet_delete(self, payload):
        network_id = self._get_network_lock_id(payload)
        if not network_id:
            return
        subnet_id = payload['subnet_id']
        network = self.cache.get_network_by_subnet_id(subnet_id)
        if not network:
            return
        self.refresh_dhcp_helper(network.id)

    def _process_loop(self):
        LOG.debug("Starting _process_loop")

        pool = eventlet.GreenPool(size=8)
        while True:
            pool.spawn_n(self._process_resource_update)

    def _process_resource_update(self):
        for tmp, update in self._queue.each_update_to_next_resource():
            method = getattr(self, update.action)
            method(update.resource)

    def port_update_end(self, context, payload):
        """Handle the port.update.end notification event."""
        updated_port = dhcp.DictModel(payload['port'])
        if self.cache.is_port_message_stale(updated_port):
            LOG.debug("Discarding stale port update: %s", updated_port)
            return
        update = queue.ResourceUpdate(updated_port.network_id,
                                      payload.get('priority',
                                                  DEFAULT_PRIORITY),
                                      action='_port_update',
                                      resource=updated_port)
        self._queue.add(update)

    @_wait_if_syncing
    def _port_update(self, updated_port):
        if self.cache.is_port_message_stale(updated_port):
            LOG.debug("Discarding stale port update: %s", updated_port)
            return
        network = self.cache.get_network_by_id(updated_port.network_id)
        if not network:
            return
        self.reload_allocations(updated_port, network)

    def reload_allocations(self, port, network):
        LOG.info("Trigger reload_allocations for port %s", port)
        driver_action = 'reload_allocations'
        if self._is_port_on_this_agent(port):
            orig = self.cache.get_port_by_id(port['id'])
            # assume IP change if not in cache
            orig = orig or {'fixed_ips': []}
            old_ips = {i['ip_address'] for i in orig['fixed_ips'] or []}
            new_ips = {i['ip_address'] for i in port['fixed_ips']}
            old_subs = {i['subnet_id'] for i in orig['fixed_ips'] or []}
            new_subs = {i['subnet_id'] for i in port['fixed_ips']}
            if new_subs != old_subs:
                # subnets being serviced by port have changed, this could
                # indicate a subnet_delete is in progress. schedule a
                # resync rather than an immediate restart so we don't
                # attempt to re-allocate IPs at the same time the server
                # is deleting them.
                self.schedule_resync("Agent port was modified",
                                     port.network_id)
                return
            elif old_ips != new_ips:
                LOG.debug("Agent IPs on network %s changed from %s to %s",
                          network.id, old_ips, new_ips)
                driver_action = 'restart'
        self.cache.put_port(port)
        self.call_driver(driver_action, network)
        self.dhcp_ready_ports.add(port.id)
        self.update_isolated_metadata_proxy(network)

    def _is_port_on_this_agent(self, port):
        thishost = utils.get_dhcp_agent_device_id(
            port['network_id'], self.conf.host)
        return port['device_id'] == thishost

    def port_create_end(self, context, payload):
        """Handle the port.create.end notification event."""
        created_port = dhcp.DictModel(payload['port'])
        update = queue.ResourceUpdate(created_port.network_id,
                                      payload.get('priority',
                                                  DEFAULT_PRIORITY),
                                      action='_port_create',
                                      resource=created_port)
        self._queue.add(update)

    @_wait_if_syncing
    def _port_create(self, created_port):
        network = self.cache.get_network_by_id(created_port.network_id)
        if not network:
            return
        new_ips = {i['ip_address'] for i in created_port['fixed_ips']}
        for port_cached in network.ports:
            # if in the same network there are ports cached with the same
            # ip address but different MAC address and/or different id,
            # this indicate that the cache is out of sync
            cached_ips = {i['ip_address']
                          for i in port_cached['fixed_ips']}
            if (new_ips.intersection(cached_ips) and
                (created_port['id'] != port_cached['id'] or
                 created_port['mac_address'] != port_cached['mac_address'])):
                self.schedule_resync("Duplicate IP addresses found, "
                                     "DHCP cache is out of sync",
                                     created_port.network_id)
                return
        self.reload_allocations(created_port, network)

    def port_delete_end(self, context, payload):
        """Handle the port.delete.end notification event."""
        network_id = self._get_network_lock_id(payload)
        if not network_id:
            return
        update = queue.ResourceUpdate(network_id,
                                      payload.get('priority',
                                                  DEFAULT_PRIORITY),
                                      action='_port_delete',
                                      resource=payload)
        self._queue.add(update)

    @_wait_if_syncing
    def _port_delete(self, payload):
        network_id = self._get_network_lock_id(payload)
        if not network_id:
            return
        port_id = payload['port_id']
        port = self.cache.get_port_by_id(port_id)
        self.cache.deleted_ports.add(port_id)
        if not port:
            return
        network = self.cache.get_network_by_id(port.network_id)
        self.cache.remove_port(port)
        if self._is_port_on_this_agent(port):
            # the agent's port has been deleted. disable the service
            # and add the network to the resync list to create
            # (or acquire a reserved) port.
            self.call_driver('disable', network)
            self.schedule_resync("Agent port was deleted", port.network_id)
        else:
            self.call_driver('reload_allocations', network)
            self.update_isolated_metadata_proxy(network)

    def update_isolated_metadata_proxy(self, network):
        """Spawn or kill metadata proxy.

        According to return from driver class, spawn or kill the metadata
        proxy process. Spawn an existing metadata proxy or kill a nonexistent
        metadata proxy will just silently return.
        """
        should_enable_metadata = self.dhcp_driver_cls.should_enable_metadata(
            self.conf, network)
        if should_enable_metadata:
            self.enable_isolated_metadata_proxy(network)
        else:
            self.disable_isolated_metadata_proxy(network)

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
                    LOG.warning("%(port_num)d router ports found on the "
                                "metadata access network. Only the port "
                                "%(port_id)s, for router %(router_id)s "
                                "will be considered",
                                {'port_num': len(router_ports),
                                 'port_id': router_ports[0].id,
                                 'router_id': router_ports[0].device_id})
                all_subnets = self.dhcp_driver_cls._get_all_subnets(network)
                if self.dhcp_driver_cls.has_metadata_subnet(all_subnets):
                    kwargs = {'router_id': router_ports[0].device_id}
                    self._metadata_routers[network.id] = (
                        router_ports[0].device_id)

        metadata_driver.MetadataDriver.spawn_monitored_metadata_proxy(
            self._process_monitor, network.namespace, dhcp.METADATA_PORT,
            self.conf, bind_address=dhcp.METADATA_DEFAULT_IP, **kwargs)

    def disable_isolated_metadata_proxy(self, network):
        if (self.conf.enable_metadata_network and
            network.id in self._metadata_routers):
            uuid = self._metadata_routers[network.id]
            is_router_id = True
        else:
            uuid = network.id
            is_router_id = False
        metadata_driver.MetadataDriver.destroy_monitored_metadata_proxy(
            self._process_monitor, uuid, self.conf, network.namespace)
        if is_router_id:
            del self._metadata_routers[network.id]


class DhcpPluginApi(object):
    """Agent side of the dhcp rpc API.

    This class implements the client side of an rpc interface.  The server side
    of this interface can be found in
    neutron.api.rpc.handlers.dhcp_rpc.DhcpRpcCallback.  For more information
    about changing rpc interfaces, see
    doc/source/contributor/internals/rpc_api.rst.

    API version history:
        1.0 - Initial version.
        1.1 - Added get_active_networks_info, create_dhcp_port,
              and update_dhcp_port methods.
        1.5 - Added dhcp_ready_on_ports

    """

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(
                topic=topic,
                namespace=n_const.RPC_NAMESPACE_DHCP_PLUGIN,
                version='1.0')
        self.client = n_rpc.get_client(target)

    @property
    def context(self):
        # TODO(kevinbenton): the context should really be passed in to each of
        # these methods so a call can be tracked all of the way through the
        # system but that will require a larger refactor to pass the context
        # everywhere. We just generate a new one here on each call so requests
        # can be independently tracked server side.
        return context.get_admin_context_without_session()

    def get_active_networks_info(self, **kwargs):
        """Make a remote process call to retrieve all network info."""
        cctxt = self.client.prepare(version='1.1')
        networks = cctxt.call(self.context, 'get_active_networks_info',
                              host=self.host, **kwargs)
        return [dhcp.NetModel(n) for n in networks]

    def get_network_info(self, network_id):
        """Make a remote process call to retrieve network info."""
        cctxt = self.client.prepare()
        network = cctxt.call(self.context, 'get_network_info',
                             network_id=network_id, host=self.host)
        if network:
            return dhcp.NetModel(network)

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

    def dhcp_ready_on_ports(self, port_ids):
        """Notify the server that DHCP is configured for the port."""
        cctxt = self.client.prepare(version='1.5')
        return cctxt.call(self.context, 'dhcp_ready_on_ports',
                          port_ids=port_ids)


class NetworkCache(object):
    """Agent cache of the current network state."""
    def __init__(self):
        self.cache = {}
        self.subnet_lookup = {}
        self.port_lookup = {}
        self.deleted_ports = set()

    def is_port_message_stale(self, payload):
        orig = self.get_port_by_id(payload['id']) or {}
        if orig.get('revision_number', 0) > payload.get('revision_number', 0):
            return True
        if payload['id'] in self.deleted_ports:
            return True
        return False

    def get_port_ids(self, network_ids=None):
        if not network_ids:
            return self.port_lookup.keys()
        return (p_id for p_id, net in self.port_lookup.items()
                if net in network_ids)

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

        non_local_subnets = getattr(network, 'non_local_subnets', [])
        for subnet in (network.subnets + non_local_subnets):
            self.subnet_lookup[subnet.id] = network.id

        for port in network.ports:
            self.port_lookup[port.id] = network.id

    def remove(self, network):
        del self.cache[network.id]

        non_local_subnets = getattr(network, 'non_local_subnets', [])
        for subnet in (network.subnets + non_local_subnets):
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
            non_local_subnets = getattr(network, 'non_local_subnets', [])
            num_subnets += len(network.subnets)
            num_subnets += len(non_local_subnets)
            num_ports += len(network.ports)
        return {'networks': num_nets,
                'subnets': num_subnets,
                'ports': num_ports}


class DhcpAgentWithStateReport(DhcpAgent):
    def __init__(self, host=None, conf=None):
        super(DhcpAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.agent_state = {
            'binary': 'neutron-dhcp-agent',
            'host': host,
            'availability_zone': self.conf.AGENT.availability_zone,
            'topic': topics.DHCP_AGENT,
            'configurations': {
                'dhcp_driver': self.conf.dhcp_driver,
                'dhcp_lease_duration': self.conf.dhcp_lease_duration,
                'log_agent_heartbeats': self.conf.AGENT.log_agent_heartbeats},
            'start_flag': True,
            'agent_type': constants.AGENT_TYPE_DHCP}
        report_interval = self.conf.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self.agent_state.get('configurations').update(
                self.cache.get_state())
            ctx = context.get_admin_context_without_session()
            agent_status = self.state_rpc.report_state(
                ctx, self.agent_state, True)
            if agent_status == agent_consts.AGENT_REVIVED:
                LOG.info("Agent has just been revived. "
                         "Scheduling full sync")
                self.schedule_resync("Agent has just been revived")
        except AttributeError:
            # This means the server does not support report_state
            LOG.warning("Neutron server does not support state report. "
                        "State report for this agent will be disabled.")
            self.heartbeat.stop()
            self.run()
            return
        except Exception:
            LOG.exception("Failed reporting state!")
            return
        if self.agent_state.pop('start_flag', None):
            self.run()

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.schedule_resync(_("Agent updated: %(payload)s") %
                             {"payload": payload})
        LOG.info("agent_updated by server side %s!", payload)

    def after_start(self):
        LOG.info("DHCP agent started")
