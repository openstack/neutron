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
from operator import itemgetter

from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib import constants
from neutron_lib.objects import exceptions
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import utils as agent_utils
from neutron.objects import agent as agent_obj
from neutron.objects import network
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
            fields = ['network_id', 'enable_dhcp', 'segment_id']
            subnets = plugin.get_subnets(context, fields=fields)
            net_ids = {}
            net_segment_ids = collections.defaultdict(set)
            for s in subnets:
                if s['enable_dhcp']:
                    net_segment_ids[s['network_id']].add(s.get('segment_id'))
            for network_id, segment_ids in net_segment_ids.items():
                is_routed_network = any(segment_ids)
                net_ids[network_id] = is_routed_network
            if not net_ids:
                LOG.debug('No non-hosted networks')
                return False
            dhcp_agents = agent_obj.Agent.get_objects(
                context, agent_type=constants.AGENT_TYPE_DHCP,
                host=host, admin_state_up=True)

            segment_host_mapping = network.SegmentHostMapping.get_objects(
                context, host=host)

            segments_on_host = {s.segment_id for s in segment_host_mapping}

            for dhcp_agent in dhcp_agents:
                if agent_utils.is_agent_down(
                    dhcp_agent.heartbeat_timestamp):
                    LOG.warning('DHCP agent %s is not active', dhcp_agent.id)
                    continue
                for net_id, is_routed_network in net_ids.items():
                    agents = plugin.get_dhcp_agents_hosting_networks(
                        context, [net_id])
                    segments_on_network = net_segment_ids[net_id]
                    if is_routed_network:
                        if len(segments_on_network & segments_on_host) == 0:
                            continue
                    else:
                        if len(agents) >= agents_per_network:
                            continue
                    if any(dhcp_agent.id == agent.id for agent in agents):
                        continue
                    net = plugin.get_network(context, net_id)
                    az_hints = (net.get(az_def.AZ_HINTS) or
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
           - for AZs with same amount of scheduled agents, the AZ which
             contains least weight agent will be used first
           - choose agent in the AZ with WeightScheduler
        """
        # The dict to record the agents in each AZ, the record will be sorted
        # according to the weight of agent. So that the agent with less weight
        # will be used first.
        hostable_az_agents = collections.defaultdict(list)
        # The dict to record the number of agents in each AZ. When the number
        # of agents in each AZ is the same and num_agents_needed is less than
        # the number of AZs, we want to select agents with less weight.
        # Use an OrderedDict here, so that the AZ with least weight agent
        # will be recorded first in the case described above. And, as a result,
        # the agent with least weight will be used first.
        num_az_agents = collections.OrderedDict()
        # resource_hostable_agents should be a list with agents in the order of
        # their weight.
        resource_hostable_agents = (
            super(AZAwareWeightScheduler, self).select(
                plugin, context, resource_hostable_agents,
                resource_hosted_agents, len(resource_hostable_agents)))
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

        chosen_agents = []
        while num_agents_needed > 0:
            # 'min' will stably output the first min value in the list.
            select_az = min(num_az_agents.items(), key=itemgetter(1))[0]
            # Select the agent in AZ with least weight.
            select_agent = hostable_az_agents[select_az][0]
            chosen_agents.append(select_agent)
            # Update the AZ-agents records.
            del hostable_az_agents[select_az][0]
            if not hostable_az_agents[select_az]:
                del num_az_agents[select_az]
            else:
                num_az_agents[select_az] += 1
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
            try:
                network.NetworkDhcpAgentBinding(context,
                     dhcp_agent_id=agent_id, network_id=network_id).create()
            except exceptions.NeutronDbObjectDuplicateEntry:
                # it's totally ok, someone just did our job!
                bound_agents.remove(agent)
                LOG.info('Agent %s already present', agent_id)
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

    def _filter_agents_with_network_access(self, plugin, context,
                                           network, hostable_agents):
        if 'candidate_hosts' in network:
            hostable_dhcp_hosts = network['candidate_hosts']
        else:
            hostable_dhcp_hosts = plugin.filter_hosts_with_network_access(
                context, network['id'],
                [agent['host'] for agent in hostable_agents])
        reachable_agents = [agent for agent in hostable_agents
                            if agent['host'] in hostable_dhcp_hosts]
        return reachable_agents

    def _get_dhcp_agents_hosting_network(self, plugin, context, network):
        """Return dhcp agents hosting the given network or None if a given
           network is already hosted by enough number of agents.
        """
        agents_per_network = cfg.CONF.dhcp_agents_per_network
        #TODO(gongysh) don't schedule the networks with only
        # subnets whose enable_dhcp is false
        with context.session.begin(subtransactions=True):
            network_hosted_agents = plugin.get_dhcp_agents_hosting_networks(
                context, [network['id']], hosts=network.get('candidate_hosts'))
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
            active_dhcp_agents = plugin.get_agent_objects(
                context, filters=filters)
            if not active_dhcp_agents:
                LOG.warning('No more DHCP agents')
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
        az_hints = (network.get(az_def.AZ_HINTS) or
                    cfg.CONF.default_availability_zones)
        active_dhcp_agents = self._get_active_agents(plugin, context, az_hints)
        hosted_agent_ids = [agent['id'] for agent in hosted_agents]
        if not active_dhcp_agents:
            return {'n_agents': 0, 'hostable_agents': [],
                    'hosted_agents': hosted_agents}
        hostable_dhcp_agents = [
            agent for agent in active_dhcp_agents
            if agent.id not in hosted_agent_ids and plugin.is_eligible_agent(
                context, True, agent)]
        hostable_dhcp_agents = self._filter_agents_with_network_access(
            plugin, context, network, hostable_dhcp_agents)

        if not hostable_dhcp_agents:
            return {'n_agents': 0, 'hostable_agents': [],
                    'hosted_agents': hosted_agents}
        n_agents = min(len(hostable_dhcp_agents), n_agents)
        return {'n_agents': n_agents, 'hostable_agents': hostable_dhcp_agents,
                'hosted_agents': hosted_agents}
