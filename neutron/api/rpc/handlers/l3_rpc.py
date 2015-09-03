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

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
import six

from neutron.common import constants
from neutron.common import exceptions
from neutron.common import utils
from neutron import context as neutron_context
from neutron.db import api as db_api
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.i18n import _LE
from neutron import manager
from neutron.plugins.common import constants as plugin_constants


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
    target = oslo_messaging.Target(version='1.6')

    @property
    def plugin(self):
        if not hasattr(self, '_plugin'):
            self._plugin = manager.NeutronManager.get_plugin()
        return self._plugin

    @property
    def l3plugin(self):
        if not hasattr(self, '_l3plugin'):
            self._l3plugin = manager.NeutronManager.get_service_plugins()[
                plugin_constants.L3_ROUTER_NAT]
        return self._l3plugin

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
        if not self.l3plugin:
            routers = {}
            LOG.error(_LE('No plugin for L3 routing registered! Will reply '
                          'to l3 agent with empty router dictionary.'))
        elif utils.is_extension_supported(
                self.l3plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.router_auto_schedule:
                self.l3plugin.auto_schedule_routers(context, host, router_ids)
            routers = (
                self.l3plugin.list_active_sync_routers_on_active_l3_agent(
                    context, host, router_ids))
        else:
            routers = self.l3plugin.get_sync_data(context, router_ids)
        if utils.is_extension_supported(
            self.plugin, constants.PORT_BINDING_EXT_ALIAS):
            self._ensure_host_set_on_ports(context, host, routers)
        LOG.debug("Routers returned to l3 agent:\n %s",
                  utils.DelayedStringRenderer(jsonutils.dumps,
                                              routers, indent=5))
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
                                              router['id'])
                for p in router.get(constants.SNAT_ROUTER_INTF_KEY, []):
                    self._ensure_host_set_on_port(context,
                                                  gw_port_host,
                                                  p, router['id'])
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
        if (port and host is not None and
            (port.get('device_owner') !=
             constants.DEVICE_OWNER_DVR_INTERFACE and
             port.get(portbindings.HOST_ID) != host or
             port.get(portbindings.VIF_TYPE) ==
             portbindings.VIF_TYPE_BINDING_FAILED)):

            # Ports owned by non-HA routers are bound again if they're
            # already bound but the router moved to another host.
            if not ha_router_port:
                # All ports, including ports created for SNAT'ing for
                # DVR are handled here
                try:
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
            # update_dvr_port_binding
            self.plugin.update_dvr_port_binding(context, port['id'],
                                                {'port':
                                                 {portbindings.HOST_ID: host,
                                                  'device_id': router_id}
                                                 })

    def get_external_network_id(self, context, **kwargs):
        """Get one external network id for l3 agent.

        l3 agent expects only one external network when it performs
        this query.
        """
        context = neutron_context.get_admin_context()
        net_id = self.plugin.get_external_network_id(context)
        LOG.debug("External network ID returned to l3 agent: %s",
                  net_id)
        return net_id

    def get_service_plugin_list(self, context, **kwargs):
        plugins = manager.NeutronManager.get_service_plugins()
        return plugins.keys()

    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Update operational status for a floating IP."""
        with context.session.begin(subtransactions=True):
            for (floatingip_id, status) in six.iteritems(fip_statuses):
                LOG.debug("New status for floating IP %(floatingip_id)s: "
                          "%(status)s", {'floatingip_id': floatingip_id,
                                         'status': status})
                try:
                    self.l3plugin.update_floatingip_status(context,
                                                           floatingip_id,
                                                           status)
                except l3.FloatingIPNotFound:
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
        filters = {'fixed_ips': {'subnet_id': [subnet_id]}}
        return self.plugin.get_ports(context, filters=filters)

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
                  'host %(host)s', {'agent_port': agent_port,
                  'host': host})
        return agent_port

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
