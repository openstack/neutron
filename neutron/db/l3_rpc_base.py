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
                                          router.get('gw_port'))
            for interface in router.get(constants.INTERFACE_KEY, []):
                self._ensure_host_set_on_port(context, plugin, host,
                                              interface)

    def _ensure_host_set_on_port(self, context, plugin, host, port):
        if (port and
            (port.get(portbindings.HOST_ID) != host or
             port.get(portbindings.VIF_TYPE) ==
             portbindings.VIF_TYPE_BINDING_FAILED)):
            plugin.update_port(context, port['id'],
                               {'port': {portbindings.HOST_ID: host}})

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
