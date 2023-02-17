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
from neutron_lib.db import api as lib_db_api
from neutron_lib.exceptions import l3 as l3_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging

from neutron.common import _constants as n_const
from neutron.common import utils
from neutron.conf.db import l3_hamode_db
from neutron.db.models import l3agent as rb_model
from neutron.objects import l3_hamode as l3_hamode_obj
from neutron.objects import l3agent as rb_obj


LOG = logging.getLogger(__name__)
cfg.CONF.register_opts(l3_hamode_db.L3_HA_OPTS)


class L3Scheduler(object, metaclass=abc.ABCMeta):

    def __init__(self):
        self.max_ha_agents = cfg.CONF.max_l3_agents_per_router

    def schedule(self, plugin, context, router_id, candidates=None):
        """Schedule the router to an active L3 agent.

        Schedule the router only if it is not already scheduled.
        """
        return self._schedule_router(
            plugin, context, router_id, candidates=candidates)

    def _router_has_binding(self, context, router_id, l3_agent_id):
        router_binding_model = rb_model.RouterL3AgentBinding

        query = context.session.query(router_binding_model.router_id)
        query = query.filter(router_binding_model.router_id == router_id,
                             router_binding_model.l3_agent_id == l3_agent_id)

        return query.count() > 0

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

    def auto_schedule_routers(self, plugin, context, host):
        """Schedule under-scheduled routers to L3 Agents.

        An under-scheduled router is a router that is either completely
        un-scheduled (scheduled to 0 agents), or an HA router that is
        under-scheduled (scheduled to less than max_l3_agents configuration
        option. The function finds all the under-scheduled routers and
        schedules them.

        :param host: if unspecified, under-scheduled routers are scheduled to
                     all agents (not necessarily from the requesting host). If
                     specified, under-scheduled routers are scheduled only to
                     the agent on 'host'.
        """
        l3_agent = plugin.get_enabled_agent_on_host(
            context, lib_const.AGENT_TYPE_L3, host)
        if not l3_agent:
            return

        underscheduled_routers = self._get_underscheduled_routers(
            plugin, context)
        target_routers = self._get_routers_can_schedule(
            plugin, context, underscheduled_routers, l3_agent)

        for router in target_routers:
            self.schedule(plugin, context, router['id'], candidates=[l3_agent])

    def _get_underscheduled_routers(self, plugin, context):
        underscheduled_routers = []
        max_agents_for_ha = plugin.get_number_of_agents_for_scheduling(context)

        for router, count in plugin.get_routers_l3_agents_count(context):
            if (count < 1 or
                    router.get('ha', False) and count < max_agents_for_ha):
                # Either the router was un-scheduled (scheduled to 0 agents),
                # or it's an HA router and it was under-scheduled (scheduled to
                # less than max_agents_for_ha). Either way, it should be added
                # to the list of routers we want to handle.
                underscheduled_routers.append(router)
        return underscheduled_routers

    def _get_candidates(self, plugin, context, sync_router):
        """Return L3 agents where a router could be scheduled."""
        is_ha = sync_router.get('ha', False)
        with lib_db_api.CONTEXT_READER.using(context):
            # allow one router is hosted by just
            # one enabled l3 agent hosting since active is just a
            # timing problem. Non-active l3 agent can return to
            # active any time
            current_l3_agents = plugin.get_l3_agents_hosting_routers(
                context, [sync_router['id']], admin_state_up=True)
            if current_l3_agents and not is_ha:
                LOG.debug('Router %(router_id)s has already been hosted '
                          'by L3 agent %(agent_id)s',
                          {'router_id': sync_router['id'],
                           'agent_id': current_l3_agents[0]['id']})
                return []

            active_l3_agents = plugin.get_l3_agents(context, active=True)
            if not active_l3_agents:
                LOG.warning('No active L3 agents')
                return []
            candidates = plugin.get_l3_agent_candidates(context,
                                                        sync_router,
                                                        active_l3_agents)
            if not candidates:
                LOG.warning('No L3 agents can host the router %s',
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

    @lib_db_api.retry_db_errors
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
        will be retried up to lib_db_api.MAX_RETRIES times.
        If, still in the HA router case, the creation failed because the
        router has already been bound to the l3 agent in question or has been
        removed (by a concurrent operation), then no further attempts will be
        made and the function will return None.

        Note that for non-HA routers, the function will always perform exactly
        one try, regardless of the error preventing the addition of a new
        RouterL3AgentBinding object to the database.
        """

        if rb_obj.RouterL3AgentBinding.objects_exist(
                context, router_id=router_id, l3_agent_id=agent_id):
            LOG.debug('Router %(router_id)s has already been scheduled '
                      'to L3 agent %(agent_id)s.',
                      {'router_id': router_id, 'agent_id': agent_id})
            return

        if not is_ha:
            binding_index = n_const.LOWEST_AGENT_BINDING_INDEX
            if rb_obj.RouterL3AgentBinding.objects_exist(
                    context, router_id=router_id, binding_index=binding_index):
                LOG.debug('Non-HA router %s has already been scheduled',
                          router_id)
                return
        else:
            binding_index = plugin.get_vacant_binding_index(
                context, router_id, is_manual_scheduling)
            if binding_index < n_const.LOWEST_AGENT_BINDING_INDEX:
                LOG.debug('Unable to find a vacant binding_index for '
                          'router %(router_id)s and agent %(agent_id)s',
                          {'router_id': router_id,
                           'agent_id': agent_id})
                return

        try:
            binding = rb_obj.RouterL3AgentBinding(
                context, l3_agent_id=agent_id,
                router_id=router_id, binding_index=binding_index)
            binding.create()
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
        return plugin.add_ha_port(ctxt, router_db.id, ha_net.network_id,
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
            with lib_db_api.CONTEXT_WRITER.using(context):
                port_binding = (
                    l3_hamode_obj.L3HARouterAgentPortBinding.get_object(
                        context, port_id=port_binding['port_id']))
                port_binding.l3_agent_id = agent['id']
                port_binding.update()
        except db_exc.DBDuplicateEntry:
            LOG.debug("Router %(router)s already scheduled for agent "
                      "%(agent)s", {'router': router_id,
                                    'agent': agent['id']})
            port_id = port_binding.port_id
            # Below call will also delete entry from L3HARouterAgentPortBinding
            # and RouterPort tables
            plugin._core_plugin.delete_port(context, port_id,
                                            l3_port_check=False)
        except l3_exc.RouterNotFound:
            LOG.debug('Router %s has already been removed '
                      'by concurrent operation', router_id)
            # we try to clear the HA network here in case the port we created
            # blocked the concurrent router delete operation from getting rid
            # of the HA network
            ha_net = plugin.get_ha_network(ctxt, tenant_id)
            if ha_net:
                plugin.safe_delete_ha_network(ctxt, ha_net, tenant_id)

    def _filter_scheduled_agents(self, plugin, context, router_id, candidates):
        hosting = plugin.get_l3_agents_hosting_routers(context, [router_id])
        # convert to comparable types
        hosting_list = [tuple(host) for host in hosting]
        return list(set(candidates) - set(hosting_list))

    def _bind_ha_router(self, plugin, context, router_id,
                        tenant_id, candidates):
        """Bind a HA router to agents based on a specific policy."""

        candidates = self._filter_scheduled_agents(plugin, context, router_id,
                                                   candidates)

        chosen_agents = self._choose_router_agents_for_ha(
            plugin, context, candidates)

        for agent in chosen_agents:
            self.create_ha_port_and_bind(plugin, context, router_id,
                                         tenant_id, agent)

        return chosen_agents


class ChanceScheduler(L3Scheduler):
    """Randomly allocate an L3 agent for a router."""

    def _choose_router_agent(self, plugin, context, candidates):
        return random.choice(candidates)

    def _choose_router_agents_for_ha(self, plugin, context, candidates):
        num_agents = self._get_num_of_agents_for_ha(len(candidates))
        return random.sample(candidates, num_agents)


class LeastRoutersScheduler(L3Scheduler):
    """Allocate to an L3 agent with the least number of routers bound."""

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
        return utils.get_az_hints(router)

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
