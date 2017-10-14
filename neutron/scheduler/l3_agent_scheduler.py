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

from neutron_lib import constants as lib_const
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import six
from sqlalchemy import sql

from neutron._i18n import _LW
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import l3_hamode_db
from neutron.db.models import l3 as l3_models
from neutron.db.models import l3agent as rb_model
from neutron.extensions import availability_zone as az_ext
from neutron.extensions import l3


LOG = logging.getLogger(__name__)
cfg.CONF.register_opts(l3_hamode_db.L3_HA_OPTS)


@six.add_metaclass(abc.ABCMeta)
class L3Scheduler(object):

    def __init__(self):
        self.max_ha_agents = cfg.CONF.max_l3_agents_per_router

    @abc.abstractmethod
    def schedule(self, plugin, context, router_id,
                 candidates=None, hints=None):
        """Schedule the router to an active L3 agent.

        Schedule the router only if it is not already scheduled.
        """
        pass

    def _router_has_binding(self, context, router_id, l3_agent_id):
        router_binding_model = rb_model.RouterL3AgentBinding

        query = context.session.query(router_binding_model)
        query = query.filter(router_binding_model.router_id == router_id,
                             router_binding_model.l3_agent_id == l3_agent_id)

        return query.count() > 0

    def _filter_unscheduled_routers(self, plugin, context, routers):
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

    def _get_unscheduled_routers(self, plugin, context):
        """Get routers with no agent binding."""
        # TODO(gongysh) consider the disabled agent's router
        no_agent_binding = ~sql.exists().where(
            l3_models.Router.id ==
            rb_model.RouterL3AgentBinding.router_id)
        query = context.session.query(
            l3_models.Router.id).filter(no_agent_binding)
        unscheduled_router_ids = [router_id_[0] for router_id_ in query]
        if unscheduled_router_ids:
            return plugin.get_routers(
                context, filters={'id': unscheduled_router_ids})
        return []

    def _get_routers_to_schedule(self, plugin, context, router_ids=None):
        """Verify that the routers specified need to be scheduled.

        :param context: the context
        :param plugin: the core plugin
        :param router_ids: the list of routers to be checked for scheduling
        :returns: the list of routers to be scheduled
        """
        if router_ids is not None:
            filters = {'id': router_ids}
            routers = plugin.get_routers(context, filters=filters)
            result = self._filter_unscheduled_routers(plugin, context, routers)
        else:
            result = self._get_unscheduled_routers(plugin, context)
        return [r for r in result
                if plugin.router_supports_scheduling(context, r['id'])]

    def _get_routers_can_schedule(self, plugin, context, routers, l3_agent):
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
            context, lib_const.AGENT_TYPE_L3, host)
        if not l3_agent:
            return

        unscheduled_routers = self._get_routers_to_schedule(
            plugin, context, router_ids)
        if not unscheduled_routers:
            if utils.is_extension_supported(
                    plugin, lib_const.L3_HA_MODE_EXT_ALIAS):
                self._schedule_ha_routers_to_additional_agent(
                    plugin, context, l3_agent)
                return

        target_routers = self._get_routers_can_schedule(
            plugin, context, unscheduled_routers, l3_agent)
        if not target_routers:
            LOG.warning(_LW('No routers compatible with L3 agent '
                            'configuration on host %s'), host)
            return

        self._bind_routers(plugin, context, target_routers, l3_agent)

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

    def _bind_routers(self, plugin, context, routers, l3_agent):
        for router in routers:
            if router.get('ha'):
                if not self._router_has_binding(context, router['id'],
                                                l3_agent.id):
                    self.create_ha_port_and_bind(
                        plugin, context, router['id'],
                        router['tenant_id'], l3_agent)
            else:
                self.bind_router(plugin, context, router['id'], l3_agent.id)

    @db_api.retry_db_errors
    def bind_router(self, plugin, context, router_id, agent_id,
                    is_manual_scheduling=False, is_ha=False):
        """Bind the router to the l3 agent which has been chosen.

        The function tries to create a RouterL3AgentBinding object and add it
        to the database. It returns the binding that was created or None if it
        failed to create it due to some conflict.

        In the HA router case, when creating a RouterL3AgentBinding (with some
        binding_index) fails because some other RouterL3AgentBinding was
        concurrently created using the same binding_index, then the function
        will retry to create an entry with a new binding_index. This creation
        will be retried up to db_api.MAX_RETRIES times.
        If, still in the HA router case, the creation failed because the
        router has already been bound to the l3 agent in question or has been
        removed (by a concurrent operation), then no further attempts will be
        made and the function will return None.

        Note that for non-HA routers, the function will always perform exactly
        one try, regardless of the error preventing the addition of a new
        RouterL3AgentBinding object to the database.
        """
        bindings = context.session.query(
            rb_model.RouterL3AgentBinding).filter_by(router_id=router_id)

        if bindings.filter_by(l3_agent_id=agent_id).first():
            LOG.debug('Router %(router_id)s has already been scheduled '
                      'to L3 agent %(agent_id)s.',
                      {'router_id': router_id, 'agent_id': agent_id})
            return

        if not is_ha:
            binding_index = rb_model.LOWEST_BINDING_INDEX
            if bindings.filter_by(binding_index=binding_index).first():
                LOG.debug('Non-HA router %s has already been scheduled',
                          router_id)
                return
        else:
            binding_index = plugin.get_vacant_binding_index(
                context, router_id, is_manual_scheduling)
            if binding_index < rb_model.LOWEST_BINDING_INDEX:
                LOG.debug('Unable to find a vacant binding_index for '
                          'router %(router_id)s and agent %(agent_id)s',
                          {'router_id': router_id,
                           'agent_id': agent_id})
                return

        try:
            with context.session.begin(subtransactions=True):
                binding = rb_model.RouterL3AgentBinding()
                binding.l3_agent_id = agent_id
                binding.router_id = router_id
                binding.binding_index = binding_index
                context.session.add(binding)
            LOG.debug('Router %(router_id)s is scheduled to L3 agent '
                      '%(agent_id)s with binding_index %(binding_index)d',
                      {'router_id': router_id,
                       'agent_id': agent_id,
                       'binding_index': binding_index})
            return binding
        except db_exc.DBReferenceError:
            LOG.debug('Router %s has already been removed '
                      'by concurrent operation', router_id)

    def _schedule_router(self, plugin, context, router_id,
                         candidates=None):
        if not plugin.router_supports_scheduling(context, router_id):
            return
        sync_router = plugin.get_router(context, router_id)
        candidates = candidates or self._get_candidates(
            plugin, context, sync_router)
        if not candidates:
            return
        elif sync_router.get('ha', False):
            chosen_agents = self._bind_ha_router(plugin, context,
                                                 router_id,
                                                 sync_router.get('tenant_id'),
                                                 candidates)
            if not chosen_agents:
                return
            chosen_agent = chosen_agents[-1]
        else:
            chosen_agent = self._choose_router_agent(
                plugin, context, candidates)
            self.bind_router(plugin, context, router_id, chosen_agent.id)
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

    def _add_port_from_net_and_ensure_vr_id(self, plugin, ctxt, router_db,
                                            tenant_id, ha_net):
        plugin._ensure_vr_id(ctxt, router_db, ha_net)
        return plugin.add_ha_port(ctxt, router_db.id, ha_net.network.id,
                                  tenant_id)

    def create_ha_port_and_bind(self, plugin, context, router_id,
                                tenant_id, agent, is_manual_scheduling=False):
        """Creates and binds a new HA port for this agent."""
        ctxt = context.elevated()
        router_db = plugin._get_router(ctxt, router_id)
        creator = functools.partial(self._add_port_from_net_and_ensure_vr_id,
                                    plugin, ctxt, router_db, tenant_id)
        dep_getter = functools.partial(plugin.get_ha_network, ctxt, tenant_id)
        dep_creator = functools.partial(plugin._create_ha_network,
                                        ctxt, tenant_id)
        dep_deleter = functools.partial(plugin._delete_ha_network, ctxt)
        dep_id_attr = 'network_id'

        # This might fail in case of concurrent calls, which is good for us
        # as we can skip the rest of this function.
        binding = self.bind_router(
            plugin, context, router_id, agent['id'],
            is_manual_scheduling=is_manual_scheduling, is_ha=True)
        if not binding:
            return

        try:
            port_binding = utils.create_object_with_dependency(
                creator, dep_getter, dep_creator,
                dep_id_attr, dep_deleter)[0]
            with db_api.autonested_transaction(context.session):
                port_binding.l3_agent_id = agent['id']
        except db_exc.DBDuplicateEntry:
            LOG.debug("Router %(router)s already scheduled for agent "
                      "%(agent)s", {'router': router_id,
                                    'agent': agent['id']})
            port_id = port_binding.port_id
            # Below call will also delete entry from L3HARouterAgentPortBinding
            # and RouterPort tables
            plugin._core_plugin.delete_port(context, port_id,
                                            l3_port_check=False)
        except l3.RouterNotFound:
            LOG.debug('Router %s has already been removed '
                      'by concurrent operation', router_id)
            # we try to clear the HA network here in case the port we created
            # blocked the concurrent router delete operation from getting rid
            # of the HA network
            ha_net = plugin.get_ha_network(ctxt, tenant_id)
            if ha_net:
                plugin.safe_delete_ha_network(ctxt, ha_net, tenant_id)

    def get_ha_routers_l3_agents_counts(self, plugin, context, filters=None):
        """Return a mapping (router, # agents) matching specified filters."""
        return plugin.get_ha_routers_l3_agents_count(context)

    def _schedule_ha_routers_to_additional_agent(self, plugin, context, agent):
        """Bind already scheduled routers to the agent.

        Retrieve the number of agents per router and check if the router has
        to be scheduled on the given agent if max_l3_agents_per_router
        is not yet reached.
        """

        routers_agents = self.get_ha_routers_l3_agents_counts(plugin, context,
                                                              agent)
        admin_ctx = context.elevated()
        underscheduled_routers = [router for router, agents in routers_agents
                                  if (not self.max_ha_agents or
                                      agents < self.max_ha_agents)]
        schedulable_routers = self._get_routers_can_schedule(
            plugin, admin_ctx, underscheduled_routers, agent)
        for router in schedulable_routers:
            if not self._router_has_binding(admin_ctx, router['id'],
                                            agent.id):
                self.create_ha_port_and_bind(plugin, admin_ctx,
                                             router['id'],
                                             router['tenant_id'],
                                             agent)

    def _bind_ha_router(self, plugin, context, router_id,
                        tenant_id, candidates):
        """Bind a HA router to agents based on a specific policy."""

        chosen_agents = self._choose_router_agents_for_ha(
            plugin, context, candidates)

        for agent in chosen_agents:
            self.create_ha_port_and_bind(plugin, context, router_id,
                                         tenant_id, agent)

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

    def _get_routers_can_schedule(self, plugin, context, routers, l3_agent):
        """Overwrite L3Scheduler's method to filter by availability zone."""
        target_routers = []
        for r in routers:
            az_hints = self._get_az_hints(r)
            if not az_hints or l3_agent['availability_zone'] in az_hints:
                target_routers.append(r)

        if not target_routers:
            return []

        return super(AZLeastRoutersScheduler, self)._get_routers_can_schedule(
            plugin, context, target_routers, l3_agent)

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

    def get_ha_routers_l3_agents_counts(self, plugin, context, filters=None):
        """Overwrite L3Scheduler's method to filter by availability zone."""
        all_routers_agents = (
            super(AZLeastRoutersScheduler, self).
            get_ha_routers_l3_agents_counts(plugin, context, filters))
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
