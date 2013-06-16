# Copyright (c) 2013 OpenStack Foundation.
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

from quantum.common import constants
from quantum.common import topics
from quantum.common import utils
from quantum import manager
from quantum.openstack.common import log as logging
from quantum.openstack.common.rpc import proxy


LOG = logging.getLogger(__name__)


class L3AgentNotifyAPI(proxy.RpcProxy):
    """API for plugin to notify L3 agent."""
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.L3_AGENT):
        super(L3AgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def _notification_host(self, context, method, payload, host):
        """Notify the agent that is hosting the router."""
        LOG.debug(_('Nofity agent at %(host)s the message '
                    '%(method)s'), {'host': host,
                                    'method': method})
        self.cast(
            context, self.make_msg(method,
                                   payload=payload),
            topic='%s.%s' % (topics.L3_AGENT, host))

    def _agent_notification(self, context, method, routers,
                            operation, data):
        """Notify changed routers to hosting l3 agents."""
        adminContext = context.is_admin and context or context.elevated()
        plugin = manager.QuantumManager.get_plugin()
        for router in routers:
            l3_agents = plugin.get_l3_agents_hosting_routers(
                adminContext, [router['id']],
                admin_state_up=True,
                active=True)
            for l3_agent in l3_agents:
                LOG.debug(_('Notify agent at %(topic)s.%(host)s the message '
                            '%(method)s'),
                          {'topic': l3_agent.topic,
                           'host': l3_agent.host,
                           'method': method})
                self.cast(
                    context, self.make_msg(method,
                                           routers=[router]),
                    topic='%s.%s' % (l3_agent.topic, l3_agent.host))

    def _notification(self, context, method, routers, operation, data):
        """Notify all the agents that are hosting the routers."""
        plugin = manager.QuantumManager.get_plugin()
        if utils.is_extension_supported(
            plugin, constants.AGENT_SCHEDULER_EXT_ALIAS):
            adminContext = (context.is_admin and
                            context or context.elevated())
            plugin.schedule_routers(adminContext, routers)
            self._agent_notification(
                context, method, routers, operation, data)
        else:
            self.fanout_cast(
                context, self.make_msg(method,
                                       routers=routers),
                topic=topics.L3_AGENT)

    def _notification_fanout(self, context, method, router_id):
        """Fanout the deleted router to all L3 agents."""
        LOG.debug(_('Fanout notify agent at %(topic)s the message '
                    '%(method)s on router %(router_id)s'),
                  {'topic': topics.L3_AGENT,
                   'method': method,
                   'router_id': router_id})
        self.fanout_cast(
            context, self.make_msg(method,
                                   router_id=router_id),
            topic=topics.L3_AGENT)

    def agent_updated(self, context, admin_state_up, host):
        self._notification_host(context, 'agent_updated',
                                {'admin_state_up': admin_state_up},
                                host)

    def router_deleted(self, context, router_id):
        self._notification_fanout(context, 'router_deleted', router_id)

    def routers_updated(self, context, routers, operation=None, data=None):
        if routers:
            self._notification(context, 'routers_updated', routers,
                               operation, data)

    def router_removed_from_agent(self, context, router_id, host):
        self._notification_host(context, 'router_removed_from_agent',
                                {'router_id': router_id}, host)

    def router_added_to_agent(self, context, routers, host):
        self._notification_host(context, 'router_added_to_agent',
                                routers, host)

L3AgentNotify = L3AgentNotifyAPI()
