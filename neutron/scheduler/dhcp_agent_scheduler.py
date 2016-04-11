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


import collections
import heapq

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from sqlalchemy import sql

from neutron._i18n import _LI, _LW
from neutron.common import constants
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import api as db_api
from neutron.extensions import availability_zone as az_ext
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
                    LOG.warning(_LW('DHCP agent %s is not active'),
                                dhcp_agent.id)
                    continue
                for net_id in net_ids:
                    agents = plugin.get_dhcp_agents_hosting_networks(
                        context, [net_id])
                    if len(agents) >= agents_per_network:
                        continue
                    if any(dhcp_agent.id == agent.id for agent in agents):
                        continue
                    net = plugin.get_network(context, net_id)
                    az_hints = (net.get(az_ext.AZ_HINTS) or
                                cfg.CONF.default_availability_zones)
                    if (az_hints and
                        dhcp_agent['availability_zone'] not in az_hints):
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


class AZAwareWeightScheduler(WeightScheduler):

    def select(self, plugin, context, resource_hostable_agents,
               resource_hosted_agents, num_agents_needed):
        """AZ aware scheduling
           If the network has multiple AZs, agents are scheduled as
           follows:
           - select AZ with least agents scheduled for the network
             (nondeterministic for AZs with same amount of agents scheduled)
           - choose agent in the AZ with WeightScheduler
        """
        hostable_az_agents = collections.defaultdict(list)
        num_az_agents = {}
        for agent in resource_hostable_agents:
            az_agent = agent['availability_zone']
            hostable_az_agents[az_agent].append(agent)
            if az_agent not in num_az_agents:
                num_az_agents[az_agent] = 0
        if num_agents_needed <= 0:
            return []
        for agent in resource_hosted_agents:
            az_agent = agent['availability_zone']
            if az_agent in num_az_agents:
                num_az_agents[az_agent] += 1

        num_az_q = [(value, key) for key, value in num_az_agents.items()]
        heapq.heapify(num_az_q)
        chosen_agents = []
        while num_agents_needed > 0:
            num, select_az = heapq.heappop(num_az_q)
            select_agent = super(AZAwareWeightScheduler, self).select(
                plugin, context, hostable_az_agents[select_az], [], 1)
            chosen_agents.append(select_agent[0])
            hostable_az_agents[select_az].remove(select_agent[0])
            if hostable_az_agents[select_az]:
                heapq.heappush(num_az_q, (num + 1, select_az))
            num_agents_needed -= 1
        return chosen_agents


class DhcpFilter(base_resource_filter.BaseResourceFilter):

    def bind(self, context, agents, network_id):
        """Bind the network to the agents."""
        # customize the bind logic
        bound_agents = agents[:]
        for agent in agents:
            # saving agent_id to use it after rollback to avoid
            # DetachedInstanceError
            agent_id = agent.id
            binding = agentschedulers_db.NetworkDhcpAgentBinding()
            binding.dhcp_agent_id = agent_id
            binding.network_id = network_id
            try:
                with db_api.autonested_transaction(context.session):
                    context.session.add(binding)
                    # try to actually write the changes and catch integrity
                    # DBDuplicateEntry
            except db_exc.DBDuplicateEntry:
                # it's totally ok, someone just did our job!
                bound_agents.remove(agent)
                LOG.info(_LI('Agent %s already present'), agent_id)
            LOG.debug('Network %(network_id)s is scheduled to be '
                      'hosted by DHCP agent %(agent_id)s',
                      {'network_id': network_id,
                       'agent_id': agent_id})
        super(DhcpFilter, self).bind(context, bound_agents, network_id)

    def filter_agents(self, plugin, context, network):
        """Return the agents that can host the network.

        This function returns a dictionary which has 3 keys.
        n_agents: The number of agents should be scheduled. If n_agents=0,
        all networks are already scheduled or no more agent can host the
        network.
        hostable_agents: A list of agents which can host the network.
        hosted_agents: A list of agents which already hosts the network.
        """
        agents_dict = self._get_network_hostable_dhcp_agents(
                                    plugin, context, network)
        if not agents_dict['hostable_agents'] or agents_dict['n_agents'] <= 0:
            return {'n_agents': 0, 'hostable_agents': [],
                    'hosted_agents': agents_dict['hosted_agents']}
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

    def _get_active_agents(self, plugin, context, az_hints):
        """Return a list of active dhcp agents."""
        with context.session.begin(subtransactions=True):
            filters = {'agent_type': [constants.AGENT_TYPE_DHCP],
                       'admin_state_up': [True]}
            if az_hints:
                filters['availability_zone'] = az_hints
            active_dhcp_agents = plugin.get_agents_db(
                context, filters=filters)
            if not active_dhcp_agents:
                LOG.warning(_LW('No more DHCP agents'))
                return []
        return active_dhcp_agents

    def _get_network_hostable_dhcp_agents(self, plugin, context, network):
        """Provide information on hostable DHCP agents for network.

        The returned value includes the number of agents that will actually
        host the given network, a list of DHCP agents that can host the given
        network, and a list of DHCP agents currently hosting the network.
        """
        hosted_agents = self._get_dhcp_agents_hosting_network(plugin,
                                                              context, network)
        if hosted_agents is None:
            return {'n_agents': 0, 'hostable_agents': [], 'hosted_agents': []}
        n_agents = cfg.CONF.dhcp_agents_per_network - len(hosted_agents)
        az_hints = (network.get(az_ext.AZ_HINTS) or
                    cfg.CONF.default_availability_zones)
        active_dhcp_agents = self._get_active_agents(plugin, context, az_hints)
        if not active_dhcp_agents:
            return {'n_agents': 0, 'hostable_agents': [],
                    'hosted_agents': hosted_agents}
        hostable_dhcp_agents = [
            agent for agent in set(active_dhcp_agents)
            if agent not in hosted_agents and plugin.is_eligible_agent(
                context, True, agent)
        ]

        hostable_dhcp_hosts = plugin.filter_hosts_with_network_access(
            context, network['id'],
            [agent['host'] for agent in hostable_dhcp_agents])
        hostable_dhcp_agents = [agent for agent in hostable_dhcp_agents
                                if agent['host'] in hostable_dhcp_hosts]

        if not hostable_dhcp_agents:
            return {'n_agents': 0, 'hostable_agents': [],
                    'hosted_agents': hosted_agents}
        n_agents = min(len(hostable_dhcp_agents), n_agents)
        return {'n_agents': n_agents, 'hostable_agents': hostable_dhcp_agents,
                'hosted_agents': hosted_agents}
