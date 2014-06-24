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

from oslo.config import cfg

from neutron.common import constants
from neutron.common import utils
from neutron import context as neutron_context
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as plugin_constants


LOG = logging.getLogger(__name__)


class L3RpcCallbackMixin(object):
    """A mix-in that enable L3 agent rpc support in plugin implementations."""

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
        l3plugin = manager.NeutronManager.get_service_plugins()[
            plugin_constants.L3_ROUTER_NAT]
        if not l3plugin:
            routers = {}
            LOG.error(_('No plugin for L3 routing registered! Will reply '
                        'to l3 agent with empty router dictionary.'))
        elif utils.is_extension_supported(
                l3plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.router_auto_schedule:
                l3plugin.auto_schedule_routers(context, host, router_ids)
            routers = l3plugin.list_active_sync_routers_on_active_l3_agent(
                context, host, router_ids)
        else:
            routers = l3plugin.get_sync_data(context, router_ids)
        plugin = manager.NeutronManager.get_plugin()
        if utils.is_extension_supported(
            plugin, constants.PORT_BINDING_EXT_ALIAS):
            self._ensure_host_set_on_ports(context, plugin, host, routers)
        LOG.debug(_("Routers returned to l3 agent:\n %s"),
                  jsonutils.dumps(routers, indent=5))
        return routers

    def _ensure_host_set_on_ports(self, context, plugin, host, routers):
        for router in routers:
            LOG.debug(_("Checking router: %(id)s for host: %(host)s"),
                      {'id': router['id'], 'host': host})
            self._ensure_host_set_on_port(context, plugin, host,
                                          router.get('gw_port'),
                                          router['id'])
            for interface in router.get(constants.INTERFACE_KEY, []):
                self._ensure_host_set_on_port(context, plugin, host,
                                              interface, router['id'])

    def _ensure_host_set_on_port(self, context, plugin, host, port,
                                 router_id=None):
        if (port and
            (port.get('device_owner') !=
             constants.DEVICE_OWNER_DVR_INTERFACE and
             port.get(portbindings.HOST_ID) != host or
             port.get(portbindings.VIF_TYPE) ==
             portbindings.VIF_TYPE_BINDING_FAILED)):
            # All ports, including ports created for SNAT'ing for
            # DVR are handled here
            plugin.update_port(context, port['id'],
                               {'port': {portbindings.HOST_ID: host}})
        elif (port and
              port.get('device_owner') ==
              constants.DEVICE_OWNER_DVR_INTERFACE):
            # Ports that are DVR interfaces have multiple bindings (based on
            # of hosts on which DVR router interfaces are spawned). Such
            # bindings are created/updated here by invoking
            # update_dvr_port_binding
            plugin.update_dvr_port_binding(context, port['id'],
                                           {'port':
                                            {portbindings.HOST_ID: host,
                                             'device_id': router_id}
                                            })

    def get_external_network_id(self, context, **kwargs):
        """Get one external network id for l3 agent.

        l3 agent expects only on external network when it performs
        this query.
        """
        context = neutron_context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        net_id = plugin.get_external_network_id(context)
        LOG.debug(_("External network ID returned to l3 agent: %s"),
                  net_id)
        return net_id

    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Update operational status for a floating IP."""
        l3_plugin = manager.NeutronManager.get_service_plugins()[
            plugin_constants.L3_ROUTER_NAT]
        with context.session.begin(subtransactions=True):
            for (floatingip_id, status) in fip_statuses.iteritems():
                LOG.debug(_("New status for floating IP %(floatingip_id)s: "
                            "%(status)s"), {'floatingip_id': floatingip_id,
                                            'status': status})
                try:
                    l3_plugin.update_floatingip_status(context,
                                                       floatingip_id,
                                                       status)
                except l3.FloatingIPNotFound:
                    LOG.debug(_("Floating IP: %s no longer present."),
                              floatingip_id)
            # Find all floating IPs known to have been the given router
            # for which an update was not received. Set them DOWN mercilessly
            # This situation might occur for some asynchronous backends if
            # notifications were missed
            known_router_fips = l3_plugin.get_floatingips(
                context, {'last_known_router_id': [router_id]})
            # Consider only floating ips which were disassociated in the API
            # FIXME(salv-orlando): Filtering in code should be avoided.
            # the plugin should offer a way to specify a null filter
            fips_to_disable = (fip['id'] for fip in known_router_fips
                               if not fip['router_id'])
            for fip_id in fips_to_disable:
                l3_plugin.update_floatingip_status(
                    context, fip_id, constants.FLOATINGIP_STATUS_DOWN)

    def get_ports_by_subnet(self, context, **kwargs):
        """DVR: RPC called by dvr-agent to get all ports for subnet."""
        subnet_id = kwargs.get('subnet_id')
        LOG.debug("DVR: subnet_id: %s", subnet_id)
        filters = {'fixed_ips': {'subnet_id': [subnet_id]}}
        plugin = manager.NeutronManager.get_plugin()
        return plugin.get_ports(context, filters=filters)

    def get_agent_gateway_port(self, context, **kwargs):
        """Get Agent Gateway port for FIP.

        l3 agent expects an Agent Gateway Port to be returned
        for this query.
        """
        network_id = kwargs.get('network_id')
        host = kwargs.get('host')
        admin_ctx = neutron_context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        l3plugin = manager.NeutronManager.get_service_plugins()[
            plugin_constants.L3_ROUTER_NAT]
        agent_port = l3plugin.create_fip_agent_gw_port_if_not_exists(
            admin_ctx, network_id, host)
        self._ensure_host_set_on_port(admin_ctx, plugin, host,
                                      agent_port)
        LOG.debug('Agent Gateway port returned : %(agent_port)s with '
                  'host %(host)s', {'agent_port': agent_port,
                  'host': host})
        return agent_port

    def get_snat_router_interface_ports(self, context, **kwargs):
        """Get SNAT serviced Router Port List.

        The Service Node that hosts the SNAT service requires
        the ports to service the router interfaces.
        This function will check if any available ports, if not
        it will create ports on the routers interfaces and
        will send a list to the L3 agent.
        """
        router_id = kwargs.get('router_id')
        host = kwargs.get('host')
        admin_ctx = neutron_context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        l3plugin = manager.NeutronManager.get_service_plugins()[
            plugin_constants.L3_ROUTER_NAT]
        snat_port_list = l3plugin.create_snat_intf_port_list_if_not_exists(
            admin_ctx, router_id)
        for p in snat_port_list:
            self._ensure_host_set_on_port(admin_ctx, plugin, host, p)
        LOG.debug('SNAT interface ports returned : %(snat_port_list)s '
                  'and on host %(host)s', {'snat_port_list': snat_port_list,
                  'host': host})
        return snat_port_list
