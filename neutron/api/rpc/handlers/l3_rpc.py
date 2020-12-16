# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib.api.definitions import portbindings
from neutron_lib.api import extensions
from neutron_lib import constants
from neutron_lib import context as neutron_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from sqlalchemy import orm


LOG = logging.getLogger(__name__)


class L3RpcCallback(object):
    """L3 agent RPC callback in plugin implementations."""

    # 1.0 L3PluginApi BASE_RPC_API_VERSION
    # 1.1 Support update_floatingip_statuses
    # 1.2 Added methods for DVR support
    # 1.3 Added a method that returns the list of activated services
    # 1.4 Added L3 HA update_router_state. This method was later removed,
    #     since it was unused. The RPC version was not changed
    # 1.5 Added update_ha_routers_states
    # 1.6 Added process_prefix_update to support IPv6 Prefix Delegation
    # 1.7 Added method delete_agent_gateway_port for DVR Routers
    # 1.8 Added address scope information
    # 1.9 Added get_router_ids
    # 1.10 Added update_all_ha_network_port_statuses
    # 1.11 Added get_host_ha_router_count
    # 1.12 Added get_networks
    target = oslo_messaging.Target(version='1.12')

    @property
    def plugin(self):
        if not hasattr(self, '_plugin'):
            self._plugin = directory.get_plugin()
        return self._plugin

    @property
    def l3plugin(self):
        if not hasattr(self, '_l3plugin'):
            self._l3plugin = directory.get_plugin(plugin_constants.L3)
        return self._l3plugin

    def update_all_ha_network_port_statuses(self, context, host):
        """Set HA network port to DOWN for HA routers hosted on <host>

        This will update HA network port status to down for all HA routers
        hosted on <host>. This is needed to avoid l3 agent spawning keepalived
        when l2 agent not yet wired the port. This can happen after a system
        reboot that has wiped out flows, etc and the L2 agent hasn't started up
        yet. The port will still be ACTIVE in the data model and the L3 agent
        will use that info to mistakenly think that L2 network is ready.
        By forcing into DOWN, we will require the L2 agent to essentially ack
        that the port is indeed ACTIVE by reacting to the port update and
        calling update_device_up.
        """
        if not extensions.is_extension_supported(
                self.plugin, constants.PORT_BINDING_EXT_ALIAS):
            return
        device_filter = {
            'device_owner': [constants.DEVICE_OWNER_ROUTER_HA_INTF],
            'status': [constants.PORT_STATUS_ACTIVE]}
        ports = self.plugin.get_ports(context, filters=device_filter)
        ha_ports = [p['id'] for p in ports
                    if p.get(portbindings.HOST_ID) == host]
        if not ha_ports:
            return
        LOG.debug("L3 agent on host %(host)s requested for fullsync, so "
                  "setting HA network ports %(ha_ports)s status to DOWN.",
                  {"host": host, "ha_ports": ha_ports})
        for p in ha_ports:
            try:
                self.plugin.update_port(
                    context, p,
                    {'port': {'status': constants.PORT_STATUS_DOWN}})
            except (orm.exc.StaleDataError, orm.exc.ObjectDeletedError,
                    exceptions.PortNotFound):
                pass

    def get_router_ids(self, context, host):
        """Returns IDs of routers scheduled to l3 agent on <host>

        This will autoschedule unhosted routers to l3 agent on <host> and then
        return all ids of routers scheduled to it.
        """
        if extensions.is_extension_supported(
                self.l3plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.router_auto_schedule:
                self.l3plugin.auto_schedule_routers(context, host)
        return self.l3plugin.list_router_ids_on_host(context, host)

    @db_api.retry_db_errors
    def sync_routers(self, context, **kwargs):
        """Sync routers according to filters to a specific agent.

        @param context: contain user information
        @param kwargs: host, router_ids
        @return: a list of routers
                 with their interfaces and floating_ips
        """
        router_ids = kwargs.get('router_ids')
        host = kwargs.get('host')
        context = neutron_context.get_admin_context()
        LOG.debug('Sync routers for ids %(router_ids)s in %(host)s',
                  {'router_ids': router_ids,
                   'host': host})
        routers = self._routers_to_sync(context, router_ids, host)
        if extensions.is_extension_supported(
                self.plugin, constants.PORT_BINDING_EXT_ALIAS):
            self._ensure_host_set_on_ports(context, host, routers)
            # refresh the data structure after ports are bound
            routers = self._routers_to_sync(context, router_ids, host)
        pf_plugin = directory.get_plugin(plugin_constants.PORTFORWARDING)
        if pf_plugin:
            pf_plugin.sync_port_forwarding_fip(context, routers)
        LOG.debug('The sync data for ids %(router_ids)s in %(host)s is: '
                  '%(routers)s', {'router_ids': router_ids,
                                  'host': host,
                                  'routers': routers})
        return routers

    def _routers_to_sync(self, context, router_ids, host=None):
        if extensions.is_extension_supported(
                self.l3plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            routers = (
                self.l3plugin.list_active_sync_routers_on_active_l3_agent(
                    context, host, router_ids))
        else:
            routers = self.l3plugin.get_sync_data(context, router_ids)
        return routers

    def _ensure_host_set_on_ports(self, context, host, routers):
        for router in routers:
            LOG.debug("Checking router: %(id)s for host: %(host)s",
                      {'id': router['id'], 'host': host})
            if router.get('gw_port') and router.get('distributed'):
                # '' is used to effectively clear binding of a gw port if not
                # bound (snat is not hosted on any l3 agent)
                gw_port_host = router.get('gw_port_host') or ''
                self._ensure_host_set_on_port(context,
                                              gw_port_host,
                                              router.get('gw_port'),
                                              router['id'],
                                              ha_router_port=router.get('ha'))
                for p in router.get(constants.SNAT_ROUTER_INTF_KEY, []):
                    self._ensure_host_set_on_port(
                        context, gw_port_host, p, router['id'],
                        ha_router_port=router.get('ha'))

            else:
                self._ensure_host_set_on_port(
                    context, host,
                    router.get('gw_port'),
                    router['id'],
                    ha_router_port=router.get('ha'))
            for interface in router.get(constants.INTERFACE_KEY, []):
                self._ensure_host_set_on_port(
                    context,
                    host,
                    interface,
                    router['id'],
                    ha_router_port=router.get('ha'))
            interface = router.get(constants.HA_INTERFACE_KEY)
            if interface:
                self._ensure_host_set_on_port(context, host, interface,
                                              router['id'])

    def _ensure_host_set_on_port(self, context, host, port, router_id=None,
                                 ha_router_port=False):
        not_bound = port and port.get(portbindings.VIF_TYPE) in (
            portbindings.VIF_TYPE_BINDING_FAILED,
            portbindings.VIF_TYPE_UNBOUND)
        if (port and host is not None and
            (port.get('device_owner') !=
             constants.DEVICE_OWNER_DVR_INTERFACE and
             port.get(portbindings.HOST_ID) != host or not_bound)):

            # Ports owned by non-HA routers are bound again if they're
            # already bound but the router moved to another host.
            if not ha_router_port:
                # All ports, including ports created for SNAT'ing for
                # DVR are handled here
                try:
                    LOG.debug("Updating router %(router)s port %(port)s "
                              "binding host %(host)s",
                              {"router": router_id, "port": port['id'],
                               "host": host})
                    self.plugin.update_port(
                        context,
                        port['id'],
                        {'port': {portbindings.HOST_ID: host}})
                    # updating port's host to pass actual info to l3 agent
                    port[portbindings.HOST_ID] = host
                except exceptions.PortNotFound:
                    LOG.debug("Port %(port)s not found while updating "
                              "agent binding for router %(router)s.",
                              {"port": port['id'], "router": router_id})
            # Ports owned by HA routers should only be bound once, if
            # they are unbound. These ports are moved when an agent reports
            # that one of its routers moved to the active state.
            else:
                if not port.get(portbindings.HOST_ID):
                    active_host = (
                        self.l3plugin.get_active_host_for_ha_router(
                            context, router_id))
                    if active_host:
                        host = active_host
                    # If there is currently no active router instance (For
                    # example it's a new router), the host that requested
                    # the routers (Essentially a random host) will do. The
                    # port binding will be corrected when an active is
                    # elected.
                    try:
                        LOG.debug("Updating router %(router)s port %(port)s "
                                  "binding host %(host)s",
                                  {"router": router_id, "port": port['id'],
                                   "host": host})
                        self.plugin.update_port(
                            context,
                            port['id'],
                            {'port': {portbindings.HOST_ID: host}})
                    except exceptions.PortNotFound:
                        LOG.debug("Port %(port)s not found while updating "
                                  "agent binding for router %(router)s.",
                                  {"port": port['id'], "router": router_id})
        elif (port and
              port.get('device_owner') ==
              constants.DEVICE_OWNER_DVR_INTERFACE):
            # Ports that are DVR interfaces have multiple bindings (based on
            # of hosts on which DVR router interfaces are spawned). Such
            # bindings are created/updated here by invoking
            # update_distributed_port_binding
            self.plugin.update_distributed_port_binding(
                context, port['id'],
                {'port': {portbindings.HOST_ID: host,
                          'device_id': router_id}})

    def get_service_plugin_list(self, context, **kwargs):
        return directory.get_plugins().keys()

    def get_host_ha_router_count(self, context, host):
        return self.l3plugin.get_host_ha_router_count(context, host)

    @db_api.retry_db_errors
    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Update operational status for a floating IP."""
        with db_api.CONTEXT_WRITER.using(context):
            for (floatingip_id, status) in fip_statuses.items():
                LOG.debug("New status for floating IP %(floatingip_id)s: "
                          "%(status)s", {'floatingip_id': floatingip_id,
                                         'status': status})
                try:
                    self.l3plugin.update_floatingip_status(context,
                                                           floatingip_id,
                                                           status)
                except l3_exc.FloatingIPNotFound:
                    LOG.debug("Floating IP: %s no longer present.",
                              floatingip_id)
            # Find all floating IPs known to have been the given router
            # for which an update was not received. Set them DOWN mercilessly
            # This situation might occur for some asynchronous backends if
            # notifications were missed
            known_router_fips = self.l3plugin.get_floatingips(
                context, {'last_known_router_id': [router_id]})
            # Consider only floating ips which were disassociated in the API
            # FIXME(salv-orlando): Filtering in code should be avoided.
            # the plugin should offer a way to specify a null filter
            fips_to_disable = (fip['id'] for fip in known_router_fips
                               if not fip['router_id'])
            for fip_id in fips_to_disable:
                self.l3plugin.update_floatingip_status(
                    context, fip_id, constants.FLOATINGIP_STATUS_DOWN)

    def get_ports_by_subnet(self, context, **kwargs):
        """DVR: RPC called by dvr-agent to get all ports for subnet."""
        subnet_id = kwargs.get('subnet_id')
        LOG.debug("DVR: subnet_id: %s", subnet_id)
        return self.l3plugin.get_ports_under_dvr_connected_subnet(
            context, subnet_id)

    @db_api.retry_db_errors
    def get_agent_gateway_port(self, context, **kwargs):
        """Get Agent Gateway port for FIP.

        l3 agent expects an Agent Gateway Port to be returned
        for this query.
        """
        network_id = kwargs.get('network_id')
        host = kwargs.get('host')
        admin_ctx = neutron_context.get_admin_context()
        agent_port = self.l3plugin.create_fip_agent_gw_port_if_not_exists(
            admin_ctx, network_id, host)
        self._ensure_host_set_on_port(admin_ctx, host, agent_port)
        LOG.debug('Agent Gateway port returned : %(agent_port)s with '
                  'host %(host)s',
                  {'agent_port': agent_port,
                   'host': host})
        return agent_port

    @db_api.retry_db_errors
    def update_ha_routers_states(self, context, **kwargs):
        """Update states for HA routers.

        Get a map of router_id to its HA state on a host and update the DB.
        State must be in: ('active', 'standby').
        """
        states = kwargs.get('states')
        host = kwargs.get('host')

        LOG.debug('Updating HA routers states on host %s: %s', host, states)
        self.l3plugin.update_routers_states(context, states, host)

    def process_prefix_update(self, context, **kwargs):
        subnets = kwargs.get('subnets')

        updated_subnets = []
        for subnet_id, prefix in subnets.items():
            updated_subnets.append(self.plugin.update_subnet(
                                        context,
                                        subnet_id,
                                        {'subnet': {'cidr': prefix}}))
        return updated_subnets

    @db_api.retry_db_errors
    def delete_agent_gateway_port(self, context, **kwargs):
        """Delete Floatingip agent gateway port."""
        network_id = kwargs.get('network_id')
        host = kwargs.get('host')
        admin_ctx = neutron_context.get_admin_context()
        self.l3plugin.delete_floatingip_agent_gateway_port(
            admin_ctx, host, network_id)

    def get_networks(self, context, filters=None, fields=None):
        """Retrieve and return a list of networks."""
        # NOTE(adrianc): This RPC is being used by out of tree interface
        # drivers, MultiInterfaceDriver and IPoIBInterfaceDriver, located in
        # networking-mlnx.
        return self.plugin.get_networks(
            context, filters=filters, fields=fields)
