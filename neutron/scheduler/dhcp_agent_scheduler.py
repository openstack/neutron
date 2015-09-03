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


from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from sqlalchemy import sql

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.i18n import _LI, _LW
from neutron.scheduler import base_resource_filter
from neutron.scheduler import base_scheduler

LOG = logging.getLogger(__name__)


class AutoScheduler(object):

    def auto_schedule_networks(self, plugin, context, host):
        """Schedule non-hosted networks to the DHCP agent on the specified
           host.
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
                        context, [net_id])
                    if len(agents) >= agents_per_network:
                        continue
                    if any(dhcp_agent.id == agent.id for agent in agents):
                        continue
                    bindings_to_add.append((dhcp_agent, net_id))
        # do it outside transaction so particular scheduling results don't
        # make other to fail
        for agent, net_id in bindings_to_add:
            self.resource_filter.bind(context, [agent], net_id)
        return True


class ChanceScheduler(base_scheduler.BaseChanceScheduler, AutoScheduler):

    def __init__(self):
        super(ChanceScheduler, self).__init__(DhcpFilter())


class WeightScheduler(base_scheduler.BaseWeightScheduler, AutoScheduler):

    def __init__(self):
        super(WeightScheduler, self).__init__(DhcpFilter())


class DhcpFilter(base_resource_filter.BaseResourceFilter):

    def bind(self, context, agents, network_id):
        """Bind the network to the agents."""
        # customize the bind logic
        bound_agents = agents[:]
        for agent in agents:
            context.session.begin(subtransactions=True)
            # saving agent_id to use it after rollback to avoid
            # DetachedInstanceError
            agent_id = agent.id
            binding = agentschedulers_db.NetworkDhcpAgentBinding()
            binding.dhcp_agent_id = agent_id
            binding.network_id = network_id
            try:
                context.session.add(binding)
                # try to actually write the changes and catch integrity
                # DBDuplicateEntry
                context.session.commit()
            except db_exc.DBDuplicateEntry:
                # it's totally ok, someone just did our job!
                context.session.rollback()
                bound_agents.remove(agent)
                LOG.info(_LI('Agent %s already present'), agent_id)
            LOG.debug('Network %(network_id)s is scheduled to be '
                      'hosted by DHCP agent %(agent_id)s',
                      {'network_id': network_id,
                       'agent_id': agent_id})
        super(DhcpFilter, self).bind(context, bound_agents, network_id)

    def filter_agents(self, plugin, context, network):
        """Return the agents that can host the network."""
        agents_dict = self._get_network_hostable_dhcp_agents(
                                    plugin, context, network)
        if not agents_dict['hostable_agents'] or agents_dict['n_agents'] <= 0:
            return {'n_agents': 0, 'hostable_agents': []}
        return agents_dict

    def _get_dhcp_agents_hosting_network(self, plugin, context, network):
        """Return dhcp agents hosting the given network or None if a given
           network is already hosted by enough number of agents.
        """
        agents_per_network = cfg.CONF.dhcp_agents_per_network
        #TODO(gongysh) don't schedule the networks with only
        # subnets whose enable_dhcp is false
        with context.session.begin(subtransactions=True):
            network_hosted_agents = plugin.get_dhcp_agents_hosting_networks(
                context, [network['id']])
            if len(network_hosted_agents) >= agents_per_network:
                LOG.debug('Network %s is already hosted by enough agents.',
                          network['id'])
                return
        return network_hosted_agents

    def _get_active_agents(self, plugin, context):
        """Return a list of active dhcp agents."""
        with context.session.begin(subtransactions=True):
            active_dhcp_agents = plugin.get_agents_db(
                context, filters={
                    'agent_type': [constants.AGENT_TYPE_DHCP],
                    'admin_state_up': [True]})
            if not active_dhcp_agents:
                LOG.warn(_LW('No more DHCP agents'))
                return []
        return active_dhcp_agents

    def _get_network_hostable_dhcp_agents(self, plugin, context, network):
        """Return number of agents which will actually host the given network
           and a list of dhcp agents which can host the given network
        """
        hosted_agents = self._get_dhcp_agents_hosting_network(plugin,
                                                              context, network)
        if hosted_agents is None:
            return {'n_agents': 0, 'hostable_agents': []}
        n_agents = cfg.CONF.dhcp_agents_per_network - len(hosted_agents)
        active_dhcp_agents = self._get_active_agents(plugin, context)
        if not active_dhcp_agents:
            return {'n_agents': 0, 'hostable_agents': []}
        hostable_dhcp_agents = [
            agent for agent in set(active_dhcp_agents)
            if agent not in hosted_agents and plugin.is_eligible_agent(
                context, True, agent)
        ]

        if not hostable_dhcp_agents:
            return {'n_agents': 0, 'hostable_agents': []}
        n_agents = min(len(hostable_dhcp_agents), n_agents)
        return {'n_agents': n_agents, 'hostable_agents':
                hostable_dhcp_agents}
