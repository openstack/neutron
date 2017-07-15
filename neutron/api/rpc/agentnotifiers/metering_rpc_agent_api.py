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

from neutron_lib import constants
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_log import log as logging
import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron.db import agentschedulers_db

LOG = logging.getLogger(__name__)


class MeteringAgentNotifyAPI(object):
    """API for plugin to notify L3 metering agent."""

    def __init__(self, topic=topics.METERING_AGENT):
        self.topic = topic
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def _agent_notification(self, context, method, routers):
        """Notify l3 metering agents hosted by l3 agent hosts."""
        adminContext = context if context.is_admin else context.elevated()
        plugin = directory.get_plugin(plugin_constants.L3)

        l3_routers = {}
        state = agentschedulers_db.get_admin_state_up_filter()
        for router in routers:
            l3_agents = plugin.get_l3_agents_hosting_routers(
                adminContext, [router['id']],
                admin_state_up=state,
                active=True)
            for l3_agent in l3_agents:
                LOG.debug('Notify metering agent at %(topic)s.%(host)s '
                          'the message %(method)s',
                          {'topic': self.topic,
                           'host': l3_agent.host,
                           'method': method})

                l3_router = l3_routers.get(l3_agent.host, [])
                l3_router.append(router)
                l3_routers[l3_agent.host] = l3_router

        for host, routers in l3_routers.items():
            cctxt = self.client.prepare(server=host)
            cctxt.cast(context, method, routers=routers)

    def _notification_fanout(self, context, method, router_id):
        LOG.debug('Fanout notify metering agent at %(topic)s the message '
                  '%(method)s on router %(router_id)s',
                  {'topic': self.topic,
                   'method': method,
                   'router_id': router_id})
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, method, router_id=router_id)

    def _notification_host(self, context, method, host, **kwargs):
        """Notify the agent that is hosting the router."""
        LOG.debug('Notify agent at %(host)s the message '
                  '%(method)s', {'host': host,
                                 'method': method})
        cctxt = self.client.prepare(server=host)
        cctxt.cast(context, method, **kwargs)

    def _notification(self, context, method, routers):
        """Notify all the agents that are hosting the routers."""
        plugin = directory.get_plugin(plugin_constants.L3)
        if utils.is_extension_supported(
            plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            self._agent_notification(context, method, routers)
        else:
            cctxt = self.client.prepare(fanout=True)
            cctxt.cast(context, method, routers=routers)

    def router_deleted(self, context, router_id):
        self._notification_fanout(context, 'router_deleted', router_id)

    def routers_updated(self, context, routers):
        if routers:
            self._notification(context, 'routers_updated', routers)

    def update_metering_label_rules(self, context, routers):
        self._notification(context, 'update_metering_label_rules', routers)

    def add_metering_label_rule(self, context, routers):
        self._notification(context, 'add_metering_label_rule', routers)

    def remove_metering_label_rule(self, context, routers):
        self._notification(context, 'remove_metering_label_rule', routers)

    def add_metering_label(self, context, routers):
        self._notification(context, 'add_metering_label', routers)

    def remove_metering_label(self, context, routers):
        self._notification(context, 'remove_metering_label', routers)

    def routers_updated_on_host(self, context, router_ids, host):
        """Notify router updates to specific hosts hosting DVR routers."""
        self._notification_host(context, 'routers_updated', host,
                                routers=router_ids)
