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
import collections
import functools
import itertools
import random

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import six
from sqlalchemy import sql

from neutron._i18n import _LE, _LW
from neutron.common import constants
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.db import l3_hamode_db
from neutron.extensions import availability_zone as az_ext
from neutron.extensions import l3


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

    def _get_routers_to_schedule(self, context, plugin, router_ids=None):
        """Verify that the routers specified need to be scheduled.

        :param context: the context
        :param plugin: the core plugin
        :param router_ids: the list of routers to be checked for scheduling
        :returns: the list of routers to be scheduled
        """
        if router_ids is not None:
            routers = plugin.get_routers(context, filters={'id': router_ids})
            return self._filter_unscheduled_routers(context, plugin, routers)
        else:
            return self._get_unscheduled_routers(context, plugin)

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

        unscheduled_routers = self._get_routers_to_schedule(
            context, plugin, router_ids)
        if not unscheduled_routers:
            if utils.is_extension_supported(
                    plugin, constants.L3_HA_MODE_EXT_ALIAS):
                return self._schedule_ha_routers_to_additional_agent(
                    plugin, context, l3_agent)

        target_routers = self._get_routers_can_schedule(
            context, plugin, unscheduled_routers, l3_agent)
        if not target_routers:
            LOG.warning(_LW('No routers compatible with L3 agent '
                            'configuration on host %s'), host)
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
            current_l3_agents = plugin.get_l3_agents_hosting_routers(
                context, [sync_router['id']], admin_state_up=True)
            if current_l3_agents:
                LOG.debug('Router %(router_id)s has already been hosted '
                          'by L3 agent %(agent_id)s',
                          {'router_id': sync_router['id'],
                           'agent_id': current_l3_agents[0]['id']})
                return []

            active_l3_agents = plugin.get_l3_agents(context, active=True)
            if not active_l3_agents:
                LOG.warning(_LW('No active L3 agents'))
                return []
            candidates = plugin.get_l3_agent_candidates(context,
                                                        sync_router,
                                                        active_l3_agents)
            if not candidates:
                LOG.warning(_LW('No L3 agents can host the router %s'),
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
        candidates = candidates or self._get_candidates(
            plugin, context, sync_router)
        if not candidates:
            return
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

    def _add_port_from_net(self, plugin, ctxt, router_id, tenant_id, ha_net):
        """small wrapper function to unpack network id from ha_network"""
        return plugin.add_ha_port(ctxt, router_id, ha_net.network.id,
                                  tenant_id)

    def create_ha_port_and_bind(self, plugin, context, router_id,
                                tenant_id, agent):
        """Creates and binds a new HA port for this agent."""
        ctxt = context.elevated()
        creator = functools.partial(self._add_port_from_net,
                                    plugin, ctxt, router_id, tenant_id)
        dep_getter = functools.partial(plugin.get_ha_network, ctxt, tenant_id)
        dep_creator = functools.partial(plugin._create_ha_network,
                                        ctxt, tenant_id)
        dep_id_attr = 'network_id'
        try:
            port_binding = utils.create_object_with_dependency(
                creator, dep_getter, dep_creator, dep_id_attr)[0]
            with db_api.autonested_transaction(context.session):
                port_binding.l3_agent_id = agent['id']
        except db_exc.DBDuplicateEntry:
            LOG.debug("Router %(router)s already scheduled for agent "
                      "%(agent)s", {'router': router_id, 'agent': agent['id']})
        except l3.RouterNotFound:
            LOG.debug('Router %s has already been removed '
                      'by concurrent operation', router_id)
            return

        self.bind_router(context, router_id, agent)

    def get_ha_routers_l3_agents_counts(self, context, plugin, filters=None):
        """Return a mapping (router, # agents) matching specified filters."""
        return plugin.get_ha_routers_l3_agents_count(context)

    def _schedule_ha_routers_to_additional_agent(self, plugin, context, agent):
        """Bind already scheduled routers to the agent.

        Retrieve the number of agents per router and check if the router has
        to be scheduled on the given agent if max_l3_agents_per_router
        is not yet reached.
        """

        routers_agents = self.get_ha_routers_l3_agents_counts(context, plugin,
                                                              agent)
        scheduled = False
        admin_ctx = context.elevated()
        for router, agents in routers_agents:
            max_agents_not_reached = (
                not self.max_ha_agents or agents < self.max_ha_agents)
            if max_agents_not_reached:
                if not self._router_has_binding(admin_ctx, router['id'],
                                                agent.id):
                    self.create_ha_port_and_bind(plugin, admin_ctx,
                                                 router['id'],
                                                 router['tenant_id'],
                                                 agent)
                    scheduled = True

        return scheduled

    def _bind_ha_router_to_agents(self, plugin, context, router_id,
                                 chosen_agents):
        port_bindings = plugin.get_ha_router_port_bindings(context,
                                                           [router_id])
        for port_binding, agent in zip(port_bindings, chosen_agents):
            try:
                with db_api.autonested_transaction(context.session):
                    port_binding.l3_agent_id = agent.id
                    self.bind_router(context, router_id, agent)
            except db_exc.DBDuplicateEntry:
                LOG.debug("Router %(router)s already scheduled for agent "
                          "%(agent)s", {'router': router_id,
                                        'agent': agent.id})
            else:
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


class AZLeastRoutersScheduler(LeastRoutersScheduler):
    """Availability zone aware scheduler.

       If a router is ha router, allocate L3 agents distributed AZs
       according to router's az_hints.
    """
    def _get_az_hints(self, router):
        return (router.get(az_ext.AZ_HINTS) or
                cfg.CONF.default_availability_zones)

    def _get_routers_can_schedule(self, context, plugin, routers, l3_agent):
        """Overwrite L3Scheduler's method to filter by availability zone."""
        target_routers = []
        for r in routers:
            az_hints = self._get_az_hints(r)
            if not az_hints or l3_agent['availability_zone'] in az_hints:
                target_routers.append(r)

        if not target_routers:
            return

        return super(AZLeastRoutersScheduler, self)._get_routers_can_schedule(
            context, plugin, target_routers, l3_agent)

    def _get_candidates(self, plugin, context, sync_router):
        """Overwrite L3Scheduler's method to filter by availability zone."""
        all_candidates = (
            super(AZLeastRoutersScheduler, self)._get_candidates(
                plugin, context, sync_router))

        candidates = []
        az_hints = self._get_az_hints(sync_router)
        for agent in all_candidates:
            if not az_hints or agent['availability_zone'] in az_hints:
                candidates.append(agent)

        return candidates

    def get_ha_routers_l3_agents_counts(self, context, plugin, filters=None):
        """Overwrite L3Scheduler's method to filter by availability zone."""
        all_routers_agents = (
            super(AZLeastRoutersScheduler, self).
            get_ha_routers_l3_agents_counts(context, plugin, filters))
        if filters is None:
            return all_routers_agents

        routers_agents = []
        for router, agents in all_routers_agents:
            az_hints = self._get_az_hints(router)
            if az_hints and filters['availability_zone'] not in az_hints:
                continue
            routers_agents.append((router, agents))

        return routers_agents

    def _choose_router_agents_for_ha(self, plugin, context, candidates):
        ordered_agents = plugin.get_l3_agents_ordered_by_num_routers(
            context, [candidate['id'] for candidate in candidates])
        num_agents = self._get_num_of_agents_for_ha(len(ordered_agents))

        # Order is kept in each az
        group_by_az = collections.defaultdict(list)
        for agent in ordered_agents:
            az = agent['availability_zone']
            group_by_az[az].append(agent)

        selected_agents = []
        for az, agents in itertools.cycle(group_by_az.items()):
            if not agents:
                continue
            selected_agents.append(agents.pop(0))
            if len(selected_agents) >= num_agents:
                break
        return selected_agents
