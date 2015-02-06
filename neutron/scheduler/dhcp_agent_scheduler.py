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

from oslo_config import cfg
from oslo_db import exception as db_exc
from sqlalchemy import sql

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.i18n import _LI, _LW
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class ChanceScheduler(object):
    """Allocate a DHCP agent for a network in a random way.
    More sophisticated scheduler (similar to filter scheduler in nova?)
    can be introduced later.
    """

    def _schedule_bind_network(self, context, agents, network_id):
        for agent in agents:
            context.session.begin(subtransactions=True)
            try:
                binding = agentschedulers_db.NetworkDhcpAgentBinding()
                binding.dhcp_agent = agent
                binding.network_id = network_id
                context.session.add(binding)
                # try to actually write the changes and catch integrity
                # DBDuplicateEntry
                context.session.commit()
            except db_exc.DBDuplicateEntry:
                # it's totally ok, someone just did our job!
                context.session.rollback()
                LOG.info(_LI('Agent %s already present'), agent)
            LOG.debug('Network %(network_id)s is scheduled to be '
                      'hosted by DHCP agent %(agent_id)s',
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
                LOG.debug('Network %s is hosted already',
                          network['id'])
                return
            n_agents = agents_per_network - len(dhcp_agents)
            enabled_dhcp_agents = plugin.get_agents_db(
                context, filters={
                    'agent_type': [constants.AGENT_TYPE_DHCP],
                    'admin_state_up': [True]})
            if not enabled_dhcp_agents:
                LOG.warn(_LW('No more DHCP agents'))
                return
            active_dhcp_agents = [
                agent for agent in set(enabled_dhcp_agents)
                if not agents_db.AgentDbMixin.is_agent_down(
                    agent['heartbeat_timestamp'])
                and agent not in dhcp_agents
            ]
            if not active_dhcp_agents:
                LOG.warn(_LW('No more DHCP agents'))
                return
            n_agents = min(len(active_dhcp_agents), n_agents)
            chosen_agents = random.sample(active_dhcp_agents, n_agents)
        self._schedule_bind_network(context, chosen_agents, network['id'])
        return chosen_agents

    def auto_schedule_networks(self, plugin, context, host):
        """Schedule non-hosted networks to the DHCP agent on
        the specified host.
        """
        agents_per_network = cfg.CONF.dhcp_agents_per_network
        # a list of (agent, net_ids) tuples
        bindings_to_add = []
        with context.session.begin(subtransactions=True):
            fields = ['network_id', 'enable_dhcp']
            subnets = plugin.get_subnets(context, fields=fields)
            net_ids = set(s['network_id'] for s in subnets
                          if s['enable_dhcp'])
            if not net_ids:
                LOG.debug('No non-hosted networks')
                return False
            query = context.session.query(agents_db.Agent)
            query = query.filter(agents_db.Agent.agent_type ==
                                 constants.AGENT_TYPE_DHCP,
                                 agents_db.Agent.host == host,
                                 agents_db.Agent.admin_state_up == sql.true())
            dhcp_agents = query.all()
            for dhcp_agent in dhcp_agents:
                if agents_db.AgentDbMixin.is_agent_down(
                    dhcp_agent.heartbeat_timestamp):
                    LOG.warn(_LW('DHCP agent %s is not active'), dhcp_agent.id)
                    continue
                for net_id in net_ids:
                    agents = plugin.get_dhcp_agents_hosting_networks(
                        context, [net_id], active=True)
                    if len(agents) >= agents_per_network:
                        continue
                    if any(dhcp_agent.id == agent.id for agent in agents):
                        continue
                    bindings_to_add.append((dhcp_agent, net_id))
        # do it outside transaction so particular scheduling results don't
        # make other to fail
        for agent, net_id in bindings_to_add:
            self._schedule_bind_network(context, [agent], net_id)
        return True
