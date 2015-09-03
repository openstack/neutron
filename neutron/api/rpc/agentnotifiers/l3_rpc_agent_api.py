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

import random

from oslo_log import log as logging
import oslo_messaging

from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron.db import agentschedulers_db
from neutron.i18n import _LE
from neutron import manager
from neutron.plugins.common import constants as service_constants


LOG = logging.getLogger(__name__)


class L3AgentNotifyAPI(object):
    """API for plugin to notify L3 agent."""

    def __init__(self, topic=topics.L3_AGENT):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def _notification_host(self, context, method, payload, host):
        """Notify the agent that is hosting the router."""
        LOG.debug('Notify agent at %(host)s the message '
                  '%(method)s', {'host': host,
                                 'method': method})
        cctxt = self.client.prepare(server=host)
        cctxt.cast(context, method, payload=payload)

    def _agent_notification(self, context, method, router_ids, operation,
                            shuffle_agents):
        """Notify changed routers to hosting l3 agents."""
        adminContext = context if context.is_admin else context.elevated()
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        state = agentschedulers_db.get_admin_state_up_filter()
        for router_id in router_ids:
            l3_agents = plugin.get_l3_agents_hosting_routers(
                adminContext, [router_id],
                admin_state_up=state,
                active=True)
            if shuffle_agents:
                random.shuffle(l3_agents)
            for l3_agent in l3_agents:
                LOG.debug('Notify agent at %(topic)s.%(host)s the message '
                          '%(method)s',
                          {'topic': l3_agent.topic,
                           'host': l3_agent.host,
                           'method': method})
                cctxt = self.client.prepare(topic=l3_agent.topic,
                                            server=l3_agent.host,
                                            version='1.1')
                cctxt.cast(context, method, routers=[router_id])

    def _agent_notification_arp(self, context, method, router_id,
                                operation, data):
        """Notify arp details to l3 agents hosting router."""
        if not router_id:
            return
        adminContext = (context.is_admin and
                        context or context.elevated())
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        state = agentschedulers_db.get_admin_state_up_filter()
        l3_agents = (plugin.
                     get_l3_agents_hosting_routers(adminContext,
                                                   [router_id],
                                                   admin_state_up=state,
                                                   active=True))
        # TODO(murali): replace cast with fanout to avoid performance
        # issues at greater scale.
        for l3_agent in l3_agents:
            log_topic = '%s.%s' % (l3_agent.topic, l3_agent.host)
            LOG.debug('Casting message %(method)s with topic %(topic)s',
                      {'topic': log_topic, 'method': method})
            dvr_arptable = {'router_id': router_id,
                            'arp_table': data}
            cctxt = self.client.prepare(topic=l3_agent.topic,
                                        server=l3_agent.host,
                                        version='1.2')
            cctxt.cast(context, method, payload=dvr_arptable)

    def _notification(self, context, method, router_ids, operation,
                      shuffle_agents, schedule_routers=True):
        """Notify all the agents that are hosting the routers."""
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if not plugin:
            LOG.error(_LE('No plugin for L3 routing registered. Cannot notify '
                          'agents with the message %s'), method)
            return
        if utils.is_extension_supported(
                plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            adminContext = (context.is_admin and
                            context or context.elevated())
            if schedule_routers:
                plugin.schedule_routers(adminContext, router_ids)
            self._agent_notification(
                context, method, router_ids, operation, shuffle_agents)
        else:
            cctxt = self.client.prepare(fanout=True)
            cctxt.cast(context, method, routers=router_ids)

    def _notification_fanout(self, context, method, router_id):
        """Fanout the deleted router to all L3 agents."""
        LOG.debug('Fanout notify agent at %(topic)s the message '
                  '%(method)s on router %(router_id)s',
                  {'topic': topics.L3_AGENT,
                   'method': method,
                   'router_id': router_id})
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, method, router_id=router_id)

    def agent_updated(self, context, admin_state_up, host):
        self._notification_host(context, 'agent_updated',
                                {'admin_state_up': admin_state_up},
                                host)

    def router_deleted(self, context, router_id):
        self._notification_fanout(context, 'router_deleted', router_id)

    def routers_updated(self, context, router_ids, operation=None, data=None,
                        shuffle_agents=False, schedule_routers=True):
        if router_ids:
            self._notification(context, 'routers_updated', router_ids,
                               operation, shuffle_agents, schedule_routers)

    def add_arp_entry(self, context, router_id, arp_table, operation=None):
        self._agent_notification_arp(context, 'add_arp_entry', router_id,
                                     operation, arp_table)

    def del_arp_entry(self, context, router_id, arp_table, operation=None):
        self._agent_notification_arp(context, 'del_arp_entry', router_id,
                                     operation, arp_table)

    def router_removed_from_agent(self, context, router_id, host):
        self._notification_host(context, 'router_removed_from_agent',
                                {'router_id': router_id}, host)

    def router_added_to_agent(self, context, router_ids, host):
        self._notification_host(context, 'router_added_to_agent',
                                router_ids, host)
