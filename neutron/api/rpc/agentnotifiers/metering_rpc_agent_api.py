# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as service_constants

LOG = logging.getLogger(__name__)


class MeteringAgentNotifyAPI(n_rpc.RpcProxy):
    """API for plugin to notify L3 metering agent."""
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.METERING_AGENT):
        super(MeteringAgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def _agent_notification(self, context, method, routers):
        """Notify l3 metering agents hosted by l3 agent hosts."""
        adminContext = context.is_admin and context or context.elevated()
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)

        l3_routers = {}
        for router in routers:
            l3_agents = plugin.get_l3_agents_hosting_routers(
                adminContext, [router['id']],
                admin_state_up=True,
                active=True)
            for l3_agent in l3_agents:
                LOG.debug(_('Notify metering agent at %(topic)s.%(host)s '
                            'the message %(method)s'),
                          {'topic': self.topic,
                           'host': l3_agent.host,
                           'method': method})

                l3_router = l3_routers.get(l3_agent.host, [])
                l3_router.append(router)
                l3_routers[l3_agent.host] = l3_router

        for host, routers in l3_routers.iteritems():
            self.cast(context, self.make_msg(method, routers=routers),
                      topic='%s.%s' % (self.topic, host))

    def _notification_fanout(self, context, method, router_id):
        LOG.debug(_('Fanout notify metering agent at %(topic)s the message '
                    '%(method)s on router %(router_id)s'),
                  {'topic': self.topic,
                   'method': method,
                   'router_id': router_id})
        self.fanout_cast(
            context, self.make_msg(method,
                                   router_id=router_id))

    def _notification(self, context, method, routers):
        """Notify all the agents that are hosting the routers."""
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if utils.is_extension_supported(
            plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            self._agent_notification(context, method, routers)
        else:
            self.fanout_cast(context, self.make_msg(method, routers=routers))

    def router_deleted(self, context, router_id):
        self._notification_fanout(context, 'router_deleted', router_id)

    def routers_updated(self, context, routers):
        if routers:
            self._notification(context, 'routers_updated', routers)

    def update_metering_label_rules(self, context, routers):
        self._notification(context, 'update_metering_label_rules', routers)

    def add_metering_label(self, context, routers):
        self._notification(context, 'add_metering_label', routers)

    def remove_metering_label(self, context, routers):
        self._notification(context, 'remove_metering_label', routers)
