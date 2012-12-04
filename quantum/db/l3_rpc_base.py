# Copyright (c) 2012 OpenStack, LLC.
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

from quantum import context as quantum_context
from quantum import manager
from quantum.openstack.common import jsonutils
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class L3RpcCallbackMixin(object):
    """A mix-in that enable L3 agent rpc support in plugin implementations."""

    def sync_routers(self, context, **kwargs):
        """Sync routers according to filters to a specific agent.

        @param context: contain user information
        @param kwargs: host, or router_id
        @return: a list of routers
                 with their interfaces and floating_ips
        """
        router_id = kwargs.get('router_id')
        # TODO(gongysh) we will use host in kwargs for multi host BP
        context = quantum_context.get_admin_context()
        plugin = manager.QuantumManager.get_plugin()
        routers = plugin.get_sync_data(context, router_id)
        LOG.debug(_("Routers returned to l3 agent:\n %s"),
                  jsonutils.dumps(routers, indent=5))
        return routers

    def get_external_network_id(self, context, **kwargs):
        """Get one external network id for l3 agent.

        l3 agent expects only on external network when it performs
        this query.
        """
        context = quantum_context.get_admin_context()
        plugin = manager.QuantumManager.get_plugin()
        net_id = plugin.get_external_network_id(context)
        LOG.debug(_("External network ID returned to l3 agent: %s"),
                  net_id)
        return net_id
