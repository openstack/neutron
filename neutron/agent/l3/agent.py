# Copyright 2012 VMware, Inc.  All rights reserved.
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

import functools
import threading

import netaddr
from neutron_lib.agent import constants as agent_consts
from neutron_lib.agent import topics
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_const
from neutron_lib import context as n_context
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_context import context as common_context
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from oslo_service import loopingcall
from oslo_service import periodic_task
from oslo_utils import excutils
from oslo_utils import netutils
from oslo_utils import timeutils
from osprofiler import profiler

from neutron.agent.common import resource_processing_queue as queue
from neutron.agent.common import utils as common_utils
from neutron.agent.l3 import dvr
from neutron.agent.l3 import dvr_edge_ha_router
from neutron.agent.l3 import dvr_edge_router as dvr_router
from neutron.agent.l3 import dvr_local_router
from neutron.agent.l3 import ha
from neutron.agent.l3 import ha_router
from neutron.agent.l3 import l3_agent_extension_api as l3_ext_api
from neutron.agent.l3 import l3_agent_extensions_manager as l3_ext_manager
from neutron.agent.l3 import legacy_router
from neutron.agent.l3 import namespace_manager
from neutron.agent.l3 import namespaces as l3_namespaces
from neutron.agent.linux import external_process
from neutron.agent.metadata import driver as metadata_driver
from neutron.agent import rpc as agent_rpc
from neutron.common import utils
from neutron import manager

LOG = logging.getLogger(__name__)

# Number of routers to fetch from server at a time on resync.
# Needed to reduce load on server side and to speed up resync on agent side.
SYNC_ROUTERS_MAX_CHUNK_SIZE = 256
SYNC_ROUTERS_MIN_CHUNK_SIZE = 32

# Priorities - lower value is higher priority
PRIORITY_RELATED_ROUTER = 0
PRIORITY_RPC = 1
PRIORITY_SYNC_ROUTERS_TASK = 2

# Actions
DELETE_ROUTER = 1
DELETE_RELATED_ROUTER = 2
ADD_UPDATE_ROUTER = 3
ADD_UPDATE_RELATED_ROUTER = 4
UPDATE_NETWORK = 5

RELATED_ACTION_MAP = {DELETE_ROUTER: DELETE_RELATED_ROUTER,
                      ADD_UPDATE_ROUTER: ADD_UPDATE_RELATED_ROUTER}

ROUTER_PROCESS_THREADS = 32


def log_verbose_exc(message, router_payload):
    LOG.exception(message)
    LOG.debug("Payload:\n%s",
              utils.DelayedStringRenderer(jsonutils.dumps,
                                          router_payload, indent=5))


class L3PluginApi:
    """Agent side of the l3 agent RPC API.

    API version history:
        1.0 - Initial version.
        1.1 - Floating IP operational status updates
        1.2 - DVR support: new L3 plugin methods added.
              - get_ports_by_subnet
              - get_agent_gateway_port
              Needed by the agent when operating in DVR/DVR_SNAT mode
        1.3 - Get the list of activated services
        1.4 - Added L3 HA update_router_state. This method was reworked in
              to update_ha_routers_states
        1.5 - Added update_ha_routers_states
        1.6 - Added process_prefix_update
        1.7 - DVR support: new L3 plugin methods added.
              - delete_agent_gateway_port
        1.8 - Added address scope information
        1.9 - Added get_router_ids
        1.10 Added update_all_ha_network_port_statuses
        1.11 Added get_host_ha_router_count
        1.12 Added get_networks
        1.13 Removed get_external_network_id
        1.14 Removed process_prefix_update
    """

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    @utils.timecost
    def get_routers(self, context, router_ids=None):
        """Make a remote process call to retrieve the sync data for routers."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'sync_routers', host=self.host,
                          router_ids=router_ids)

    @utils.timecost
    def update_all_ha_network_port_statuses(self, context):
        """Make a remote process call to update HA network port status."""
        cctxt = self.client.prepare(version='1.10')
        return cctxt.call(context, 'update_all_ha_network_port_statuses',
                          host=self.host)

    @utils.timecost
    def get_router_ids(self, context):
        """Make a remote process call to retrieve scheduled routers ids."""
        cctxt = self.client.prepare(version='1.9')
        return cctxt.call(context, 'get_router_ids', host=self.host)

    @utils.timecost
    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Call the plugin update floating IPs's operational status."""
        cctxt = self.client.prepare(version='1.1')
        return cctxt.call(context, 'update_floatingip_statuses',
                          router_id=router_id, fip_statuses=fip_statuses)

    @utils.timecost
    def get_ports_by_subnet(self, context, subnet_id):
        """Retrieve ports by subnet id."""
        cctxt = self.client.prepare(version='1.2')
        return cctxt.call(context, 'get_ports_by_subnet', host=self.host,
                          subnet_id=subnet_id)

    @utils.timecost
    def get_agent_gateway_port(self, context, fip_net):
        """Get or create an agent_gateway_port."""
        cctxt = self.client.prepare(version='1.2')
        return cctxt.call(context, 'get_agent_gateway_port',
                          network_id=fip_net, host=self.host)

    @utils.timecost
    def get_service_plugin_list(self, context):
        """Make a call to get the list of activated services."""
        cctxt = self.client.prepare(version='1.3')
        return cctxt.call(context, 'get_service_plugin_list')

    @utils.timecost
    def update_ha_routers_states(self, context, states):
        """Update HA routers states."""
        cctxt = self.client.prepare(version='1.5')
        return cctxt.cast(context, 'update_ha_routers_states',
                          host=self.host, states=states)

    @utils.timecost
    def delete_agent_gateway_port(self, context, fip_net):
        """Delete Floatingip_agent_gateway_port."""
        cctxt = self.client.prepare(version='1.7')
        return cctxt.call(context, 'delete_agent_gateway_port',
                          host=self.host, network_id=fip_net)

    @utils.timecost
    def get_host_ha_router_count(self, context):
        """Make a call to get the count of HA router."""
        cctxt = self.client.prepare(version='1.11')
        return cctxt.call(context, 'get_host_ha_router_count', host=self.host)

    def get_networks(self, context, filters=None, fields=None):
        """Get networks.

        :param context: Security context
        :param filters: The filters to apply.
                        E.g {"id" : ["<uuid of a network>", ...]}
        :param fields: A list of fields to collect, e.g ["id", "subnets"].
        :return: A list of dicts where each dict represent a network object.
        """

        cctxt = self.client.prepare(version='1.12')
        return cctxt.call(
            context, 'get_networks', filters=filters, fields=fields)


class RouterFactory:

    def __init__(self):
        self._routers = {}

    def register(self, features, router_cls):
        """Register router class which implements BaseRouterInfo

        Features which is a list of strings converted to frozenset internally
        for key uniqueness.

        :param features: a list of strings of router's features
        :param router_cls: a router class which implements BaseRouterInfo
        """
        self._routers[frozenset(features)] = router_cls

    def create(self, features, **kwargs):
        """Create router instance with registered router class

        :param features: a list of strings of router's features
        :param kwargs: arguments for router class
        :returns: a router instance which implements BaseRouterInfo
        :raises: n_exc.RouterNotFoundInRouterFactory
        """
        try:
            router = self._routers[frozenset(features)]
            return router(**kwargs)
        except KeyError:
            exc = l3_exc.RouterNotFoundInRouterFactory(
                router_id=kwargs['router_id'], features=features)
            LOG.exception(exc.msg)
            raise exc


@profiler.trace_cls("l3-agent")
class L3NATAgent(ha.AgentMixin,
                 dvr.AgentMixin,
                 manager.Manager):
    """Manager for L3NatAgent

        API version history:
        1.0 initial Version
        1.1 changed the type of the routers parameter
            to the routers_updated method.
            It was previously a list of routers in dict format.
            It is now a list of router IDs only.
            Per rpc versioning rules,  it is backwards compatible.
        1.2 - DVR support: new L3 agent methods added.
              - add_arp_entry
              - del_arp_entry
        1.3 - fipnamespace_delete_on_ext_net - to delete fipnamespace
              after the external network is removed
              Needed by the L3 service when dealing with DVR
        1.4 - support network_update to get MTU updates
    """
    target = oslo_messaging.Target(version='1.4')

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.check_config()
        self.router_info = {}
        self.router_factory = RouterFactory()
        self._register_router_cls(self.router_factory)

        self._check_config_params()

        self.process_monitor = None
        self._context = n_context.get_admin_context_without_session()

        self.target_ex_net_id = None
        self.use_ipv6 = netutils.is_ipv6_enabled()
        self.fullsync = True
        self._exiting = False
        self.sync_routers_chunk_size = SYNC_ROUTERS_MAX_CHUNK_SIZE
        super().__init__(host=self.conf.host)

    def init_host(self):
        super().init_host()
        self.process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='router')
        self.plugin_rpc = L3PluginApi(topics.L3PLUGIN, self.host)
        self.driver = common_utils.load_interface_driver(
            self.conf,
            get_networks_callback=functools.partial(
                self.plugin_rpc.get_networks, self.context))

        # Get the HA router count from Neutron Server
        # This is the first place where we contact neutron-server on startup
        # so retry in case its not ready to respond.
        while True:
            try:
                self.ha_router_count = int(
                    self.plugin_rpc.get_host_ha_router_count(self.context))
            except oslo_messaging.MessagingTimeout as e:
                LOG.warning('l3-agent cannot contact neutron server '
                            'to retrieve HA router count. '
                            'Check connectivity to neutron server. '
                            'Retrying... '
                            'Detailed message: %(msg)s.', {'msg': e})
                continue
            break
        LOG.info("Agent HA routers count %s", self.ha_router_count)

        self.init_extension_manager(self.plugin_rpc)

        self.metadata_driver = None
        if self.conf.enable_metadata_proxy:
            self.metadata_driver = metadata_driver.MetadataDriver(self)

        self.namespaces_manager = namespace_manager.NamespaceManager(
            self.conf,
            self.driver,
            self.metadata_driver)

        # L3 agent router processing Thread Pool Executor
        self._pool = utils.ThreadPoolExecutorWithBlock(
            max_workers=ROUTER_PROCESS_THREADS)
        self._queue = queue.ResourceProcessingQueue()

        # Consume network updates to trigger router resync
        consumers = [[topics.NETWORK, topics.UPDATE]]
        agent_rpc.create_consumers([self], topics.AGENT, consumers)

        self._check_ha_router_process_status()

    def check_config(self):
        if self.conf.cleanup_on_shutdown:
            LOG.warning("cleanup_on_shutdown is set to True, so L3 agent will "
                        "cleanup all its routers when exiting, "
                        "data-plane will be affected.")

    def _check_ha_router_process_status(self):
        """Check HA router VRRP process status in network node.

        Check if the HA router HA routers VRRP (keepalived) process count
        and state change python monitor process count meet the expected
        quantity. If so, l3-agent will not call neutron to set all related
        HA port to down state, this can prevent some unexpected VRRP
        re-election. If not, a physical host may have down and just
        restarted, set HA network port status to DOWN.
        """
        if (self.conf.agent_mode not in [lib_const.L3_AGENT_MODE_DVR_SNAT,
                                         lib_const.L3_AGENT_MODE_LEGACY]):
            return

        if self.ha_router_count <= 0:
            return

        # Only set HA ports down when host was rebooted so no net
        # namespaces were still created.
        if any(ns.startswith(l3_namespaces.NS_PREFIX) for ns in
               self.namespaces_manager.list_all()):
            LOG.debug("Network configuration already done. Skipping"
                      " set HA port to DOWN state.")
            return

        LOG.debug("Call neutron server to set HA port to DOWN state.")
        try:
            # We set HA network port status to DOWN to let l2 agent
            # update it to ACTIVE after wiring. This allows us to spawn
            # keepalived only when l2 agent finished wiring the port.
            self.plugin_rpc.update_all_ha_network_port_statuses(
                self.context)
        except Exception:
            LOG.exception('update_all_ha_network_port_statuses failed')

    def _register_router_cls(self, factory):
        factory.register([], legacy_router.LegacyRouter)
        factory.register(['ha'], ha_router.HaRouter)

        if self.conf.agent_mode == lib_const.L3_AGENT_MODE_DVR_SNAT:
            factory.register(['distributed'],
                             dvr_router.DvrEdgeRouter)
            factory.register(['ha', 'distributed'],
                             dvr_edge_ha_router.DvrEdgeHaRouter)
        else:
            factory.register(['distributed'],
                             dvr_local_router.DvrLocalRouter)
            factory.register(['ha', 'distributed'],
                             dvr_local_router.DvrLocalRouter)

    def _check_config_params(self):
        """Check items in configuration files.

        Check for required and invalid configuration items.
        The actual values are not verified for correctness.
        """
        if not self.conf.interface_driver:
            msg = 'An interface driver must be specified'
            LOG.error(msg)
            raise SystemExit(1)

        if self.conf.ipv6_gateway:
            # ipv6_gateway configured. Check for valid v6 link-local address.
            try:
                msg = ("%s used in config as ipv6_gateway is not a valid "
                       "IPv6 link-local address.")
                ip_addr = netaddr.IPAddress(self.conf.ipv6_gateway)
                if ip_addr.version != 6 or not ip_addr.is_link_local():
                    LOG.error(msg, self.conf.ipv6_gateway)
                    raise SystemExit(1)
            except netaddr.AddrFormatError:
                LOG.error(msg, self.conf.ipv6_gateway)
                raise SystemExit(1)

    def _create_router(self, router_id, router):
        kwargs = {
            'agent': self,
            'router_id': router_id,
            'router': router,
            'use_ipv6': self.use_ipv6,
            'agent_conf': self.conf,
            'interface_driver': self.driver,
        }

        features = []
        if router.get('distributed'):
            features.append('distributed')
            kwargs['host'] = self.host

        if router.get('ha'):
            features.append('ha')

        if router.get('distributed') and router.get('ha'):
            # Case 1: If the router contains information about the HA interface
            # and if the requesting agent is a DVR_SNAT agent then go ahead
            # and create a HA router.
            # Case 2: If the router does not contain information about the HA
            # interface this means that this DVR+HA router needs to host only
            # the edge side of it, typically because it's landing on a node
            # that needs to provision a router namespace because of a DVR
            # service port (e.g. DHCP). So go ahead and create a regular DVR
            # edge router.
            if (not router.get(lib_const.HA_INTERFACE_KEY) or
                    self.conf.agent_mode != lib_const.L3_AGENT_MODE_DVR_SNAT):
                features.remove('ha')

        return self.router_factory.create(features, **kwargs)

    def _router_added(self, router_id, router):
        ri = self._create_router(router_id, router)
        registry.publish(resources.ROUTER, events.BEFORE_CREATE, self,
                         payload=events.DBEventPayload(
                             self.context,
                             resource_id=router_id,
                             states=(ri,)))

        self.router_info[router_id] = ri

        # If initialize() fails, cleanup and retrigger complete sync
        try:
            ri.initialize(self.process_monitor)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Error while initializing router %s',
                              router_id)
                self._cleanup_failed_router(router_id, delete_router_info=True)

    def _cleanup_failed_router(self, router_id, delete_router_info):
        ri = self.router_info.pop(router_id)
        self.namespaces_manager.ensure_router_cleanup(router_id)
        try:
            if delete_router_info:
                ri.delete()
        except Exception:
            LOG.exception('Error while deleting router %s',
                          router_id)

    def _safe_router_removed(self, router_id):
        """Try to delete a router and return True if successful."""
        # The l3_ext_manager API expects a router dict, look it up
        ri = self.router_info.get(router_id)

        try:
            if ri:
                self.l3_ext_manager.delete_router(self.context, ri.router)
            self._router_removed(ri, router_id)
        except Exception:
            LOG.exception('Error while deleting router %s', router_id)
            return False

        return True

    def _router_removed(self, ri, router_id):
        """Delete the router and stop the auxiliary processes

        This stops the auxiliary processes (keepalived, keepvalived-state-
        change, radvd, etc) and deletes the router ports and the namespace.
        The "router_info" cache is updated too at the beginning of the process,
        to avoid any other concurrent process to handle the router being
        deleted. If an exception is raised, the "router_info" cache is
        restored.
        """
        if ri is None:
            LOG.warning("Info for router %s was not found. "
                        "Performing router cleanup", router_id)
            self.namespaces_manager.ensure_router_cleanup(router_id)
            return

        registry.publish(resources.ROUTER, events.BEFORE_DELETE, self,
                         payload=events.DBEventPayload(
                             self.context, states=(ri,),
                             resource_id=router_id))

        del self.router_info[router_id]
        try:
            ri.delete()
        except Exception:
            with excutils.save_and_reraise_exception():
                self.router_info[router_id] = ri
        LOG.debug("Router info %s delete action done, "
                  "and it was removed from cache.", router_id)

        registry.publish(resources.ROUTER, events.AFTER_DELETE, self,
                         payload=events.DBEventPayload(
                             self.context,
                             resource_id=router_id,
                             states=(ri,)))

    def init_extension_manager(self, connection):
        l3_ext_manager.register_opts(self.conf)
        self.agent_api = l3_ext_api.L3AgentExtensionAPI(self.router_info,
                                                        self.router_factory)
        self.l3_ext_manager = (
            l3_ext_manager.L3AgentExtensionsManager(self.conf))
        self.l3_ext_manager.initialize(
            connection, lib_const.L3_AGENT_MODE,
            self.agent_api)

    def router_deleted(self, context, router_id):
        """Deal with router deletion RPC message."""
        LOG.debug('Got router deleted notification for %s', router_id)
        update = queue.ResourceUpdate(router_id,
                                      PRIORITY_RPC,
                                      action=DELETE_ROUTER)
        self._queue.add(update)

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        LOG.debug('Got routers updated notification :%s', routers)
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            for id in routers:
                update = queue.ResourceUpdate(
                    id, PRIORITY_RPC, action=ADD_UPDATE_ROUTER)
                self._queue.add(update)

    def router_removed_from_agent(self, context, payload):
        LOG.debug('Got router removed from agent :%r', payload)
        router_id = payload['router_id']
        update = queue.ResourceUpdate(router_id,
                                      PRIORITY_RPC,
                                      action=DELETE_ROUTER)
        self._queue.add(update)

    def router_added_to_agent(self, context, payload):
        LOG.debug('Got router added to agent :%r', payload)
        self.routers_updated(context, payload)

    def network_update(self, context, **kwargs):
        network_id = kwargs['network']['id']
        LOG.debug("Got network %s update", network_id)
        for ri in self.router_info.values():
            update = queue.ResourceUpdate(ri.router_id,
                                          PRIORITY_RPC,
                                          action=UPDATE_NETWORK,
                                          resource=network_id)
            self._queue.add(update)

    def _process_network_update(self, router_id, network_id):

        def _port_belongs(p):
            return p['network_id'] == network_id

        ri = self.router_info.get(router_id)
        if not ri:
            return
        LOG.debug("Checking if router %s is plugged to the network %s",
                  ri, network_id)
        ports = list(ri.internal_ports)
        if ri.ex_gw_port:
            ports.append(ri.ex_gw_port)
        if any(_port_belongs(p) for p in ports):
            update = queue.ResourceUpdate(
                ri.router_id, PRIORITY_SYNC_ROUTERS_TASK)
            self._resync_router(update)

    def _process_router_if_compatible(self, router):
        # Either ex_net_id or handle_internal_only_routers must be set
        ex_net_id = (router['external_gateway_info'] or {}).get('network_id')
        if not ex_net_id and not self.conf.handle_internal_only_routers:
            raise l3_exc.RouterNotCompatibleWithAgent(router_id=router['id'])

        if router['id'] not in self.router_info:
            LOG.debug("Router %s info not in cache, "
                      "will do the router add action.", router['id'])
            self._process_added_router(router)
        else:
            LOG.debug("Router %s info in cache, "
                      "will do the router update action.", router['id'])
            self._process_updated_router(router)

    def _process_added_router(self, router):
        self._router_added(router['id'], router)
        ri = self.router_info[router['id']]
        ri.router = router
        try:
            ri.process()
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Error while processing router %s',
                              router['id'])
                # NOTE(slaweq): deleting of the router info in the
                # _cleanup_failed_router is avoided as in case of error,
                # processing of the router will be retried on next call and
                # that may lead to some race conditions e.g. with
                # configuration of the DVR router's FIP gateway
                self._cleanup_failed_router(router['id'],
                                            delete_router_info=False)

        registry.publish(resources.ROUTER, events.AFTER_CREATE, self,
                         payload=events.DBEventPayload(
                             self.context,
                             resource_id=router['id'],
                             states=(ri,)))

        self.l3_ext_manager.add_router(self.context, router)

    def _process_updated_router(self, router):
        ri = self.router_info[router['id']]

        router_ha = router.get('ha')
        router_distributed = router.get('distributed')
        if ((router_ha is not None and ri.router.get('ha') != router_ha) or
                (router_distributed is not None and
                 ri.router.get('distributed') != router_distributed)):
            LOG.warning('Type of the router %(id)s changed. '
                        'Old type: ha=%(old_ha)s; distributed=%(old_dvr)s; '
                        'New type: ha=%(new_ha)s; distributed=%(new_dvr)s',
                        {'id': router['id'],
                         'old_ha': ri.router.get('ha'),
                         'old_dvr': ri.router.get('distributed'),
                         'new_ha': router.get('ha'),
                         'new_dvr': router.get('distributed')})
            ri = self._create_router(router['id'], router)
            self.router_info[router['id']] = ri

        is_dvr_snat_agent = (self.conf.agent_mode ==
                             lib_const.L3_AGENT_MODE_DVR_SNAT)
        is_dvr_only_agent = (self.conf.agent_mode in
                             [lib_const.L3_AGENT_MODE_DVR,
                              lib_const.L3_AGENT_MODE_DVR_NO_EXTERNAL])
        old_router_ha_interface = ri.router.get(lib_const.HA_INTERFACE_KEY)
        current_router_ha_interface = router.get(lib_const.HA_INTERFACE_KEY)
        ha_interface_change = ((old_router_ha_interface is None and
                                current_router_ha_interface is not None) or
                               (old_router_ha_interface is not None and
                                current_router_ha_interface is None))
        is_dvr_ha_router = router.get('distributed') and router.get('ha')

        if is_dvr_snat_agent and is_dvr_ha_router and ha_interface_change:
            LOG.debug("Removing HA router %s, since it is not bound to "
                      "the current agent, and recreating regular DVR router "
                      "based on service port requirements.",
                      router['id'])
            if self._safe_router_removed(router['id']):
                self._process_added_router(router)
        else:
            is_ha_router = getattr(ri, 'ha_state', False)
            # For HA routers check that DB state matches actual state
            if router.get('ha') and not is_dvr_only_agent and is_ha_router:
                self.check_ha_state_for_router(
                    router['id'], router.get(lib_const.HA_ROUTER_STATE_KEY))
            ri.router = router
            registry.publish(resources.ROUTER, events.BEFORE_UPDATE, self,
                             payload=events.DBEventPayload(
                                 self.context,
                                 resource_id=router['id'],
                                 states=(ri,)))

            ri.process()
            registry.publish(resources.ROUTER, events.AFTER_UPDATE, self,
                             payload=events.DBEventPayload(
                                 self.context,
                                 resource_id=router['id'],
                                 states=(None, ri)))
            self.l3_ext_manager.update_router(self.context, router)

    def _resync_router(self, router_update,
                       priority=PRIORITY_SYNC_ROUTERS_TASK):
        # Don't keep trying to resync if it's failing
        if router_update.hit_retry_limit():
            LOG.warning("Hit retry limit with router update for %s, action %s",
                        router_update.id, router_update.action)
            return
        router_update.timestamp = timeutils.utcnow()
        router_update.priority = priority
        router_update.resource = None  # Force the agent to resync the router
        self._queue.add(router_update)

    def _process_update(self):
        if self._exiting:
            return

        for rp, update in self._queue.each_update_to_next_resource():
            LOG.info("Starting processing update %s, action %s, priority %s, "
                     "update_id %s. Wait time elapsed: %.3f",
                     update.id, update.action, update.priority,
                     update.update_id,
                     update.time_elapsed_since_create)
            if update.action == UPDATE_NETWORK:
                self._process_network_update(
                    router_id=update.id,
                    network_id=update.resource)
            else:
                self._process_router_update(rp, update)

    def _process_router_update(self, rp, update):
        LOG.info("Starting router update for %s, action %s, priority %s, "
                 "update_id %s. Wait time elapsed: %.3f",
                 update.id, update.action, update.priority,
                 update.update_id,
                 update.time_elapsed_since_create)

        routers = [update.resource] if update.resource else []

        not_delete_no_routers = (update.action != DELETE_ROUTER and
                                 not routers)
        related_action = update.action in (DELETE_RELATED_ROUTER,
                                           ADD_UPDATE_RELATED_ROUTER)
        if not_delete_no_routers or related_action:
            try:
                update.timestamp = timeutils.utcnow()
                routers = self.plugin_rpc.get_routers(self.context,
                                                      [update.id])
            except Exception:
                msg = "Failed to fetch router information for '%s'"
                LOG.exception(msg, update.id)
                self._resync_router(update)
                return

            # For a related action, verify the router is still hosted here,
            # since it could have just been deleted and we don't want to
            # add it back.
            if related_action:
                routers = [r for r in routers if r['id'] == update.id]

        if not routers:
            if self._safe_router_removed(update.id):
                # need to update timestamp of removed router in case
                # there are older events for the same router in the
                # processing queue (like events from fullsync) in order to
                # prevent deleted router re-creation
                rp.fetched_and_processed(update.timestamp)
            else:
                self._resync_router(update)
            LOG.info("Finished a router delete for %s, update_id %s. "
                     "Time elapsed: %.3f",
                     update.id, update.update_id,
                     update.time_elapsed_since_start)
            return

        if not self._process_routers_if_compatible(routers, update):
            self._resync_router(update)
            return

        rp.fetched_and_processed(update.timestamp)
        LOG.info("Finished a router update for %s, update_id %s. "
                 "Time elapsed: %.3f",
                 update.id, update.update_id,
                 update.time_elapsed_since_start)

    def _process_routers_if_compatible(self, routers, update):
        process_result = True
        for router in routers:
            if router['id'] != update.id:
                # Don't do the work here, instead create a new update and
                # enqueue it, since there could be another thread working
                # on it already and we don't want to race.
                new_action = RELATED_ACTION_MAP.get(
                    update.action, ADD_UPDATE_RELATED_ROUTER)
                new_update = queue.ResourceUpdate(
                    router['id'],
                    priority=PRIORITY_RELATED_ROUTER,
                    action=new_action)
                self._queue.add(new_update)
                LOG.debug('Queued a router update for %(router_id)s '
                          '(related router %(related_router_id)s). '
                          'Original event action %(action)s, '
                          'priority %(priority)s. '
                          'New event action %(new_action)s, '
                          'priority %(new_priority)s',
                          {'router_id': router['id'],
                           'related_router_id': update.id,
                           'action': update.action,
                           'priority': update.priority,
                           'new_action': new_update.action,
                           'new_priority': new_update.priority})
                continue

            try:
                self._process_router_if_compatible(router)
            except l3_exc.RouterNotCompatibleWithAgent as e:
                log_verbose_exc(e.msg, router)
                # Was the router previously handled by this agent?
                if router['id'] in self.router_info:
                    LOG.error("Removing incompatible router '%s'",
                              router['id'])
                    self._safe_router_removed(router['id'])
            except Exception:
                log_verbose_exc(
                    "Failed to process compatible router: %s" % update.id,
                    router)
                process_result = False
        return process_result

    def _process_routers_loop(self):
        LOG.debug("Starting _process_routers_loop")
        while not self._exiting:
            self._pool.submit(self._process_update)

    # NOTE(kevinbenton): this is set to 1 second because the actual interval
    # is controlled by a FixedIntervalLoopingCall in neutron/service.py that
    # is responsible for task execution.
    @periodic_task.periodic_task(spacing=1, run_immediately=True)
    def periodic_sync_routers_task(self, context):
        if not self.fullsync:
            return
        LOG.debug("Starting fullsync periodic_sync_routers_task")

        # self.fullsync is True at this point. If an exception -- caught or
        # uncaught -- prevents setting it to False below then the next call
        # to periodic_sync_routers_task will re-enter this code and try again.

        # Context manager self.namespaces_manager captures a picture of
        # namespaces *before* fetch_and_sync_all_routers fetches the full list
        # of routers from the database.  This is important to correctly
        # identify stale ones.

        try:
            with self.namespaces_manager as ns_manager:
                self.fetch_and_sync_all_routers(context, ns_manager)
        except l3_exc.AbortSyncRouters:
            self.fullsync = True

    def fetch_and_sync_all_routers(self, context, ns_manager):
        prev_router_ids = set(self.router_info)
        curr_router_ids = set()
        timestamp = timeutils.utcnow()
        router_ids = []
        chunk = []
        is_snat_agent = (self.conf.agent_mode ==
                         lib_const.L3_AGENT_MODE_DVR_SNAT)
        try:
            router_ids = self.plugin_rpc.get_router_ids(context)
            # fetch routers by chunks to reduce the load on server and to
            # start router processing earlier
            for i in range(0, len(router_ids), self.sync_routers_chunk_size):
                chunk = router_ids[i:i + self.sync_routers_chunk_size]
                routers = self.plugin_rpc.get_routers(context, chunk)
                LOG.debug('Processing :%r', routers)
                for r in routers:
                    curr_router_ids.add(r['id'])
                    ns_manager.keep_router(r['id'])
                    if r.get('distributed'):
                        # need to keep fip namespaces as well
                        ext_net_id = (r['external_gateway_info'] or {}).get(
                            'network_id')
                        if ext_net_id:
                            ns_manager.keep_ext_net(ext_net_id)
                        elif is_snat_agent and not r.get('ha'):
                            ns_manager.ensure_snat_cleanup(r['id'])
                    update = queue.ResourceUpdate(
                        r['id'],
                        PRIORITY_SYNC_ROUTERS_TASK,
                        resource=r,
                        action=ADD_UPDATE_ROUTER,
                        timestamp=timestamp)
                    self._queue.add(update)
        except oslo_messaging.MessagingTimeout:
            if self.sync_routers_chunk_size > SYNC_ROUTERS_MIN_CHUNK_SIZE:
                self.sync_routers_chunk_size = max(
                    self.sync_routers_chunk_size // 2,
                    SYNC_ROUTERS_MIN_CHUNK_SIZE)
                LOG.error('Server failed to return info for routers in '
                          'required time, decreasing chunk size to: %s',
                          self.sync_routers_chunk_size)
            else:
                LOG.error('Server failed to return info for routers in '
                          'required time even with min chunk size: %s. '
                          'It might be under very high load or '
                          'just inoperable',
                          self.sync_routers_chunk_size)
            raise
        except oslo_messaging.MessagingException:
            failed_routers = chunk or router_ids
            LOG.exception("Failed synchronizing routers '%s' "
                          "due to RPC error", failed_routers)
            raise l3_exc.AbortSyncRouters()

        self.fullsync = False
        LOG.debug("periodic_sync_routers_task successfully completed")
        # adjust chunk size after successful sync
        if self.sync_routers_chunk_size < SYNC_ROUTERS_MAX_CHUNK_SIZE:
            self.sync_routers_chunk_size = min(
                self.sync_routers_chunk_size + SYNC_ROUTERS_MIN_CHUNK_SIZE,
                SYNC_ROUTERS_MAX_CHUNK_SIZE)

        # Delete routers that have disappeared since the last sync
        for router_id in prev_router_ids - curr_router_ids:
            ns_manager.keep_router(router_id)
            update = queue.ResourceUpdate(router_id,
                                          PRIORITY_SYNC_ROUTERS_TASK,
                                          timestamp=timestamp,
                                          action=DELETE_ROUTER)
            self._queue.add(update)

    @property
    def context(self):
        # generate a new request-id on each call to make server side tracking
        # of RPC calls easier.
        self._context.request_id = common_context.generate_request_id()
        return self._context

    def stop(self):
        LOG.info("Stopping L3 agent")
        if self.conf.cleanup_on_shutdown:
            self._exiting = True
            for router in self.router_info.values():
                router.delete()


class L3NATAgentWithStateReport(L3NATAgent):
    def _report_state(self):
        num_ex_gw_ports = 0
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        for ri in router_infos:
            ex_gw_port = ri.get_ex_gw_port()
            if ex_gw_port:
                num_ex_gw_ports += 1
            num_interfaces += len(ri.router.get(lib_const.INTERFACE_KEY,
                                                []))
            num_floating_ips += len(ri.router.get(lib_const.FLOATINGIP_KEY,
                                                  []))
        configurations = self.agent_state['configurations']
        configurations['routers'] = num_routers
        configurations['ex_gw_ports'] = num_ex_gw_ports
        configurations['interfaces'] = num_interfaces
        configurations['floating_ips'] = num_floating_ips
        try:
            agent_status = self.state_rpc.report_state(self.context,
                                                       self.agent_state,
                                                       True)
            if agent_status == agent_consts.AGENT_REVIVED:
                LOG.info('Agent has just been revived. '
                         'Doing a full sync.')
                self.fullsync = True
            self.agent_state.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            LOG.warning("Neutron server does not support state report. "
                        "State report for this agent will be disabled.")
            self.heartbeat.stop()
            return
        except Exception:
            self.failed_report_state = True
            LOG.exception("Failed reporting state!")
            return
        if self.failed_report_state:
            self.failed_report_state = False
            LOG.info("Successfully reported state after a previous failure.")

    def init_host(self):
        super().init_host()
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.failed_report_state = False
        self.agent_state = {
            'binary': lib_const.AGENT_PROCESS_L3,
            'host': self.host,
            'availability_zone': self.conf.AGENT.availability_zone,
            'topic': topics.L3_AGENT,
            'configurations': {
                'agent_mode': self.conf.agent_mode,
                'handle_internal_only_routers':
                self.conf.handle_internal_only_routers,
                'interface_driver': self.conf.interface_driver,
                'log_agent_heartbeats': self.conf.AGENT.log_agent_heartbeats,
                'extensions': self.l3_ext_manager.names()},
            'start_flag': True,
            'agent_type': lib_const.AGENT_TYPE_L3}
        report_interval = self.conf.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                f=self._report_state)
            self.heartbeat.start(interval=report_interval)

    def after_start(self):
        threading.Thread(target=self._process_routers_loop).start()
        LOG.info("L3 agent started")
        # Do the report state before we do the first full sync.
        self._report_state()

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info("agent_updated by server side %s!", payload)
