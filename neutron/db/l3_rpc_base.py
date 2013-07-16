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
from neutron import manager
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging


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
        plugin = manager.NeutronManager.get_plugin()
        if utils.is_extension_supported(
            plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.router_auto_schedule:
                plugin.auto_schedule_routers(context, host, router_ids)
            routers = plugin.list_active_sync_routers_on_active_l3_agent(
                context, host, router_ids)
        else:
            routers = plugin.get_sync_data(context, router_ids)
        LOG.debug(_("Routers returned to l3 agent:\n %s"),
                  jsonutils.dumps(routers, indent=5))
        return routers

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
