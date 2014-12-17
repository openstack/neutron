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

import abc
import random

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import six
from sqlalchemy import sql

from neutron.common import constants
from neutron.common import utils
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.db import l3_hamode_db
from neutron.i18n import _LE, _LW


LOG = logging.getLogger(__name__)
cfg.CONF.register_opts(l3_hamode_db.L3_HA_OPTS)


@six.add_metaclass(abc.ABCMeta)
class L3Scheduler(object):

    def __init__(self):
        self.min_ha_agents = cfg.CONF.min_l3_agents_per_router
        self.max_ha_agents = cfg.CONF.max_l3_agents_per_router

    @abc.abstractmethod
    def schedule(self, plugin, context, router_id,
                 candidates=None, hints=None):
        """Schedule the router to an active L3 agent.

        Schedule the router only if it is not already scheduled.
        """
        pass

    def _router_has_binding(self, context, router_id, l3_agent_id):
        router_binding_model = l3_agentschedulers_db.RouterL3AgentBinding

        query = context.session.query(router_binding_model)
        query = query.filter(router_binding_model.router_id == router_id,
                             router_binding_model.l3_agent_id == l3_agent_id)

        return query.count() > 0

    def _filter_unscheduled_routers(self, context, plugin, routers):
        """Filter from list of routers the ones that are not scheduled."""
        unscheduled_routers = []
        for router in routers:
            l3_agents = plugin.get_l3_agents_hosting_routers(
                context, [router['id']])
            if l3_agents:
                LOG.debug('Router %(router_id)s has already been '
                          'hosted by L3 agent %(agent_id)s',
                          {'router_id': router['id'],
                           'agent_id': l3_agents[0]['id']})
            else:
                unscheduled_routers.append(router)
        return unscheduled_routers

    def _get_unscheduled_routers(self, context, plugin):
        """Get routers with no agent binding."""
        # TODO(gongysh) consider the disabled agent's router
        no_agent_binding = ~sql.exists().where(
            l3_db.Router.id ==
            l3_agentschedulers_db.RouterL3AgentBinding.router_id)
        query = context.session.query(l3_db.Router.id).filter(no_agent_binding)
        unscheduled_router_ids = [router_id_[0] for router_id_ in query]
        if unscheduled_router_ids:
            return plugin.get_routers(
                context, filters={'id': unscheduled_router_ids})
        return []

    def _get_routers_to_schedule(self, context, plugin,
                                 router_ids=None, exclude_distributed=False):
        """Verify that the routers specified need to be scheduled.

        :param context: the context
        :param plugin: the core plugin
        :param router_ids: the list of routers to be checked for scheduling
        :param exclude_distributed: whether or not to consider dvr routers
        :returns: the list of routers to be scheduled
        """
        if router_ids is not None:
            routers = plugin.get_routers(context, filters={'id': router_ids})
            unscheduled_routers = self._filter_unscheduled_routers(
                context, plugin, routers)
        else:
            unscheduled_routers = self._get_unscheduled_routers(context,
                                                                plugin)

        if exclude_distributed:
            unscheduled_routers = [
                r for r in unscheduled_routers if not r.get('distributed')
            ]
        return unscheduled_routers

    def _get_routers_can_schedule(self, context, plugin, routers, l3_agent):
        """Get the subset of routers that can be scheduled on the L3 agent."""
        ids_to_discard = set()
        for router in routers:
            # check if the l3 agent is compatible with the router
            candidates = plugin.get_l3_agent_candidates(
                context, router, [l3_agent])
            if not candidates:
                ids_to_discard.add(router['id'])

        return [r for r in routers if r['id'] not in ids_to_discard]

    def auto_schedule_routers(self, plugin, context, host, router_ids):
        """Schedule non-hosted routers to L3 Agent running on host.

        If router_ids is given, each router in router_ids is scheduled
        if it is not scheduled yet. Otherwise all unscheduled routers
        are scheduled.
        Do not schedule the routers which are hosted already
        by active l3 agents.

        :returns: True if routers have been successfully assigned to host
        """
        l3_agent = plugin.get_enabled_agent_on_host(
            context, constants.AGENT_TYPE_L3, host)
        if not l3_agent:
            return False

        # NOTE(armando-migliaccio): DVR routers should not be auto
        # scheduled because auto-scheduling may interfere with the
        # placement rules for IR and SNAT namespaces.
        unscheduled_routers = self._get_routers_to_schedule(
            context, plugin, router_ids, exclude_distributed=True)
        if not unscheduled_routers:
            if utils.is_extension_supported(
                    plugin, constants.L3_HA_MODE_EXT_ALIAS):
                return self._schedule_ha_routers_to_additional_agent(
                    plugin, context, l3_agent)

        target_routers = self._get_routers_can_schedule(
            context, plugin, unscheduled_routers, l3_agent)
        if not target_routers:
            LOG.warn(_LW('No routers compatible with L3 agent configuration'
                         ' on host %s'), host)
            return False

        self._bind_routers(context, plugin, target_routers, l3_agent)
        return True

    def _get_candidates(self, plugin, context, sync_router):
        """Return L3 agents where a router could be scheduled."""
        with context.session.begin(subtransactions=True):
            # allow one router is hosted by just
            # one enabled l3 agent hosting since active is just a
            # timing problem. Non-active l3 agent can return to
            # active any time
            l3_agents = plugin.get_l3_agents_hosting_routers(
                context, [sync_router['id']], admin_state_up=True)
            if l3_agents and not sync_router.get('distributed', False):
                LOG.debug('Router %(router_id)s has already been hosted'
                          ' by L3 agent %(agent_id)s',
                          {'router_id': sync_router['id'],
                           'agent_id': l3_agents[0]['id']})
                return

            active_l3_agents = plugin.get_l3_agents(context, active=True)
            if not active_l3_agents:
                LOG.warn(_LW('No active L3 agents'))
                return
            new_l3agents = plugin.get_l3_agent_candidates(context,
                                                          sync_router,
                                                          active_l3_agents)
            old_l3agentset = set(l3_agents)
            if sync_router.get('distributed', False):
                new_l3agentset = set(new_l3agents)
                candidates = list(new_l3agentset - old_l3agentset)
            else:
                candidates = new_l3agents
                if not candidates:
                    LOG.warn(_LW('No L3 agents can host the router %s'),
                             sync_router['id'])

            return candidates

    def _bind_routers(self, context, plugin, routers, l3_agent):
        for router in routers:
            if router.get('ha'):
                if not self._router_has_binding(context, router['id'],
                                                l3_agent.id):
                    self.create_ha_port_and_bind(
                        plugin, context, router['id'],
                        router['tenant_id'], l3_agent)
            else:
                self.bind_router(context, router['id'], l3_agent)

    def bind_router(self, context, router_id, chosen_agent):
        """Bind the router to the l3 agent which has been chosen."""
        try:
            with context.session.begin(subtransactions=True):
                binding = l3_agentschedulers_db.RouterL3AgentBinding()
                binding.l3_agent = chosen_agent
                binding.router_id = router_id
                context.session.add(binding)
        except db_exc.DBDuplicateEntry:
            LOG.debug('Router %(router_id)s has already been scheduled '
                      'to L3 agent %(agent_id)s.',
                      {'agent_id': chosen_agent.id,
                       'router_id': router_id})
            return
        except db_exc.DBReferenceError:
            LOG.debug('Router %s has already been removed '
                      'by concurrent operation', router_id)
            return

        LOG.debug('Router %(router_id)s is scheduled to L3 agent '
                  '%(agent_id)s', {'router_id': router_id,
                                   'agent_id': chosen_agent.id})

    def _schedule_router(self, plugin, context, router_id,
                         candidates=None):
        sync_router = plugin.get_router(context, router_id)
        router_distributed = sync_router.get('distributed', False)
        if router_distributed:
            # For Distributed routers check for SNAT Binding before
            # calling the schedule_snat_router
            snat_bindings = plugin.get_snat_bindings(context, [router_id])
            router_gw_exists = sync_router.get('external_gateway_info', False)
            if not snat_bindings and router_gw_exists:
                # If GW exists for DVR routers and no SNAT binding
                # call the schedule_snat_router
                return plugin.schedule_snat_router(
                    context, router_id, sync_router)
            if not router_gw_exists and snat_bindings:
                # If DVR router and no Gateway but SNAT Binding exists then
                # call the unbind_snat_servicenode to unbind the snat service
                # from agent
                plugin.unbind_snat_servicenode(context, router_id)
                return
        candidates = candidates or self._get_candidates(
            plugin, context, sync_router)
        if not candidates:
            return
        if router_distributed:
            for chosen_agent in candidates:
                self.bind_router(context, router_id, chosen_agent)
        elif sync_router.get('ha', False):
            chosen_agents = self._bind_ha_router(plugin, context,
                                                 router_id, candidates)
            if not chosen_agents:
                return
            chosen_agent = chosen_agents[-1]
        else:
            chosen_agent = self._choose_router_agent(
                plugin, context, candidates)
            self.bind_router(context, router_id, chosen_agent)
        return chosen_agent

    @abc.abstractmethod
    def _choose_router_agent(self, plugin, context, candidates):
        """Choose an agent from candidates based on a specific policy."""
        pass

    @abc.abstractmethod
    def _choose_router_agents_for_ha(self, plugin, context, candidates):
        """Choose agents from candidates based on a specific policy."""
        pass

    def _get_num_of_agents_for_ha(self, candidates_count):
        return (min(self.max_ha_agents, candidates_count) if self.max_ha_agents
                else candidates_count)

    def _enough_candidates_for_ha(self, candidates):
        if not candidates or len(candidates) < self.min_ha_agents:
            LOG.error(_LE("Not enough candidates, a HA router needs at least "
                          "%s agents"), self.min_ha_agents)
            return False
        return True

    def create_ha_port_and_bind(self, plugin, context, router_id,
                                tenant_id, agent):
        """Creates and binds a new HA port for this agent."""
        ha_network = plugin.get_ha_network(context, tenant_id)
        port_binding = plugin.add_ha_port(context.elevated(), router_id,
                                          ha_network.network.id, tenant_id)
        port_binding.l3_agent_id = agent['id']
        self.bind_router(context, router_id, agent)

    def _schedule_ha_routers_to_additional_agent(self, plugin, context, agent):
        """Bind already scheduled routers to the agent.

        Retrieve the number of agents per router and check if the router has
        to be scheduled on the given agent if max_l3_agents_per_router
        is not yet reached.
        """

        routers_agents = plugin.get_ha_routers_l3_agents_count(context)

        scheduled = False
        admin_ctx = context.elevated()
        for router_id, tenant_id, agents in routers_agents:
            max_agents_not_reached = (
                not self.max_ha_agents or agents < self.max_ha_agents)
            if max_agents_not_reached:
                if not self._router_has_binding(admin_ctx, router_id,
                                                agent.id):
                    self.create_ha_port_and_bind(plugin, admin_ctx,
                                                 router_id, tenant_id,
                                                 agent)
                    scheduled = True

        return scheduled

    def _bind_ha_router_to_agents(self, plugin, context, router_id,
                                 chosen_agents):
        port_bindings = plugin.get_ha_router_port_bindings(context,
                                                           [router_id])
        for port_binding, agent in zip(port_bindings, chosen_agents):
            port_binding.l3_agent_id = agent.id
            self.bind_router(context, router_id, agent)

            LOG.debug('HA Router %(router_id)s is scheduled to L3 agent '
                      '%(agent_id)s)',
                      {'router_id': router_id, 'agent_id': agent.id})

    def _bind_ha_router(self, plugin, context, router_id, candidates):
        """Bind a HA router to agents based on a specific policy."""

        if not self._enough_candidates_for_ha(candidates):
            return

        chosen_agents = self._choose_router_agents_for_ha(
            plugin, context, candidates)

        self._bind_ha_router_to_agents(plugin, context, router_id,
                                       chosen_agents)

        return chosen_agents


class ChanceScheduler(L3Scheduler):
    """Randomly allocate an L3 agent for a router."""

    def schedule(self, plugin, context, router_id,
                 candidates=None):
        return self._schedule_router(
            plugin, context, router_id, candidates=candidates)

    def _choose_router_agent(self, plugin, context, candidates):
        return random.choice(candidates)

    def _choose_router_agents_for_ha(self, plugin, context, candidates):
        num_agents = self._get_num_of_agents_for_ha(len(candidates))
        return random.sample(candidates, num_agents)


class LeastRoutersScheduler(L3Scheduler):
    """Allocate to an L3 agent with the least number of routers bound."""

    def schedule(self, plugin, context, router_id,
                 candidates=None):
        return self._schedule_router(
            plugin, context, router_id, candidates=candidates)

    def _choose_router_agent(self, plugin, context, candidates):
        candidate_ids = [candidate['id'] for candidate in candidates]
        chosen_agent = plugin.get_l3_agent_with_min_routers(
            context, candidate_ids)
        return chosen_agent

    def _choose_router_agents_for_ha(self, plugin, context, candidates):
        num_agents = self._get_num_of_agents_for_ha(len(candidates))
        ordered_agents = plugin.get_l3_agents_ordered_by_num_routers(
            context, [candidate['id'] for candidate in candidates])
        return ordered_agents[:num_agents]
