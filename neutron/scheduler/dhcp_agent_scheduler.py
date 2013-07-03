# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import random

from oslo.config import cfg

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class ChanceScheduler(object):
    """Allocate a DHCP agent for a network in a random way.
    More sophisticated scheduler (similar to filter scheduler in nova?)
    can be introduced later.
    """

    def _schedule_bind_network(self, context, agent, network_id):
        binding = agentschedulers_db.NetworkDhcpAgentBinding()
        binding.dhcp_agent = agent
        binding.network_id = network_id
        context.session.add(binding)
        LOG.debug(_('Network %(network_id)s is scheduled to be hosted by '
                    'DHCP agent %(agent_id)s'),
                  {'network_id': network_id,
                   'agent_id': agent})

    def schedule(self, plugin, context, network):
        """Schedule the network to active DHCP agent(s).

        A list of scheduled agents is returned.
        """
        agents_per_network = cfg.CONF.dhcp_agents_per_network

        #TODO(gongysh) don't schedule the networks with only
        # subnets whose enable_dhcp is false
        with context.session.begin(subtransactions=True):
            dhcp_agents = plugin.get_dhcp_agents_hosting_networks(
                context, [network['id']], active=True)
            if len(dhcp_agents) >= agents_per_network:
                LOG.debug(_('Network %s is hosted already'),
                          network['id'])
                return
            n_agents = agents_per_network - len(dhcp_agents)
            enabled_dhcp_agents = plugin.get_agents_db(
                context, filters={
                    'agent_type': [constants.AGENT_TYPE_DHCP],
                    'admin_state_up': [True]})
            if not enabled_dhcp_agents:
                LOG.warn(_('No more DHCP agents'))
                return
            active_dhcp_agents = [
                agent for agent in set(enabled_dhcp_agents)
                if not agents_db.AgentDbMixin.is_agent_down(
                    agent['heartbeat_timestamp'])
                and agent not in dhcp_agents
            ]
            if not active_dhcp_agents:
                LOG.warn(_('No more DHCP agents'))
                return
            n_agents = min(len(active_dhcp_agents), n_agents)
            chosen_agents = random.sample(active_dhcp_agents, n_agents)
            for agent in chosen_agents:
                self._schedule_bind_network(context, agent, network['id'])
        return chosen_agents

    def auto_schedule_networks(self, plugin, context, host):
        """Schedule non-hosted networks to the DHCP agent on
        the specified host.
        """
        agents_per_network = cfg.CONF.dhcp_agents_per_network
        with context.session.begin(subtransactions=True):
            query = context.session.query(agents_db.Agent)
            query = query.filter(agents_db.Agent.agent_type ==
                                 constants.AGENT_TYPE_DHCP,
                                 agents_db.Agent.host == host,
                                 agents_db.Agent.admin_state_up == True)
            dhcp_agents = query.all()
            for dhcp_agent in dhcp_agents:
                if agents_db.AgentDbMixin.is_agent_down(
                    dhcp_agent.heartbeat_timestamp):
                    LOG.warn(_('DHCP agent %s is not active'), dhcp_agent.id)
                    continue
                fields = ['network_id', 'enable_dhcp']
                subnets = plugin.get_subnets(context, fields=fields)
                net_ids = set(s['network_id'] for s in subnets
                              if s['enable_dhcp'])
                if not net_ids:
                    LOG.debug(_('No non-hosted networks'))
                    return False
                for net_id in net_ids:
                    agents = plugin.get_dhcp_agents_hosting_networks(
                        context, [net_id], active=True)
                    if len(agents) >= agents_per_network:
                        continue
                    if any(dhcp_agent.id == agent.id for agent in agents):
                        continue
                    binding = agentschedulers_db.NetworkDhcpAgentBinding()
                    binding.dhcp_agent = dhcp_agent
                    binding.network_id = net_id
                    context.session.add(binding)
        return True
