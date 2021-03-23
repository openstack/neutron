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

from neutron_lib.agent import topics
from neutron_lib.api import extensions
from neutron_lib import constants
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
import oslo_messaging

from neutron.api.rpc.agentnotifiers import utils as ag_utils
from neutron.common import utils as common_utils


LOG = logging.getLogger(__name__)

# default messaging timeout is 60 sec, so 2 here is chosen to not block API
# call for more than 2 minutes
AGENT_NOTIFY_MAX_ATTEMPTS = 2


class L3AgentNotifyAPI(object):
    """API for plugin to notify L3 agent."""

    def __init__(self, topic=topics.L3_AGENT):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def _notification_host(self, context, method, host, use_call=False,
                           **kwargs):
        """Notify the agent that is hosting the router."""
        LOG.debug('Notify agent at %(host)s the message '
                  '%(method)s', {'host': host,
                                 'method': method})
        cctxt = self.client.prepare(server=host)
        rpc_method = (ag_utils.retry(cctxt.call, AGENT_NOTIFY_MAX_ATTEMPTS)
                      if use_call else cctxt.cast)
        rpc_method(context, method, **kwargs)

    def _agent_notification(self, context, method, router_ids, operation,
                            shuffle_agents):
        """Notify changed routers to hosting l3 agents."""
        adminContext = (
            context if context.is_admin else
            common_utils.get_elevated_context(context))
        plugin = directory.get_plugin(plugin_constants.L3)
        for router_id in router_ids:
            hosts = plugin.get_hosts_to_notify(adminContext, router_id)
            if shuffle_agents:
                random.shuffle(hosts)
            for host in hosts:
                LOG.debug('Notify agent at %(topic)s.%(host)s the message '
                          '%(method)s',
                          {'topic': topics.L3_AGENT,
                           'host': host,
                           'method': method})
                cctxt = self.client.prepare(topic=topics.L3_AGENT,
                                            server=host,
                                            version='1.1')
                cctxt.cast(context, method, routers=[router_id])

    def _agent_notification_arp(self, context, method, router_id,
                                operation, data):
        """Notify arp details to l3 agents hosting router."""
        if not router_id:
            return
        dvr_arptable = {'router_id': router_id, 'arp_table': data}
        LOG.debug('Fanout dvr_arptable update: %s', dvr_arptable)
        cctxt = self.client.prepare(fanout=True, version='1.2')
        cctxt.cast(context, method, payload=dvr_arptable)

    def _notification(self, context, method, router_ids, operation,
                      shuffle_agents, schedule_routers=True):
        """Notify all the agents that are hosting the routers."""
        plugin = directory.get_plugin(plugin_constants.L3)
        if not plugin:
            LOG.error('No plugin for L3 routing registered. Cannot notify '
                      'agents with the message %s', method)
            return
        if extensions.is_extension_supported(
                plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            adminContext = (
                context.is_admin and
                context or common_utils.get_elevated_context(context))
            if schedule_routers:
                plugin.schedule_routers(adminContext, router_ids)
            self._agent_notification(
                context, method, router_ids, operation, shuffle_agents)
        else:
            cctxt = self.client.prepare(fanout=True)
            cctxt.cast(context, method, routers=router_ids)

    def _notification_fanout(self, context, method, router_id=None, **kwargs):
        """Fanout the information to all L3 agents.

        This function will fanout the router_id or ext_net_id
        to the L3 Agents.
        """
        ext_net_id = kwargs.get('ext_net_id')
        if router_id:
            kwargs['router_id'] = router_id
            LOG.debug('Fanout notify agent at %(topic)s the message '
                      '%(method)s on router %(router_id)s',
                      {'topic': topics.L3_AGENT,
                       'method': method,
                       'router_id': router_id})
        if ext_net_id:
            LOG.debug('Fanout notify agent at %(topic)s the message '
                      '%(method)s for external_network  %(ext_net_id)s',
                      {'topic': topics.L3_AGENT,
                       'method': method,
                       'ext_net_id': ext_net_id})
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, method, **kwargs)

    def agent_updated(self, context, admin_state_up, host):
        self._notification_host(context, 'agent_updated', host,
                                payload={'admin_state_up': admin_state_up})

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

    def delete_fipnamespace_for_ext_net(self, context, ext_net_id):
        self._notification_fanout(
            context, 'fipnamespace_delete_on_ext_net',
            ext_net_id=ext_net_id)

    def router_removed_from_agent(self, context, router_id, host):
        self._notification_host(context, 'router_removed_from_agent', host,
                                payload={'router_id': router_id})

    def router_added_to_agent(self, context, router_ids, host):
        # need to use call here as we want to be sure agent received
        # notification and router will not be "lost". However using call()
        # itself is not a guarantee, calling code should handle exceptions and
        # retry
        self._notification_host(context, 'router_added_to_agent', host,
                                use_call=True, payload=router_ids)

    def routers_updated_on_host(self, context, router_ids, host):
        self._notification_host(context, 'routers_updated', host,
                                routers=router_ids)
