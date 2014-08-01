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

from oslo.db import exception as db_exc
import six
from sqlalchemy.orm import exc
from sqlalchemy import sql

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class L3Scheduler(object):

    @abc.abstractmethod
    def schedule(self, plugin, context, router_id,
                 candidates=None, hints=None):
        """Schedule the router to an active L3 agent.

        Schedule the router only if it is not already scheduled.
        """
        pass

    def dvr_has_binding(self, context, router_id, l3_agent_id):
        router_binding_model = l3_agentschedulers_db.RouterL3AgentBinding

        query = context.session.query(router_binding_model)
        query = query.filter(router_binding_model.router_id == router_id,
                             router_binding_model.l3_agent_id == l3_agent_id)

        return query.count() > 0

    def auto_schedule_routers(self, plugin, context, host, router_ids):
        """Schedule non-hosted routers to L3 Agent running on host.

        If router_ids is given, each router in router_ids is scheduled
        if it is not scheduled yet. Otherwise all unscheduled routers
        are scheduled.
        Don't schedule the routers which are hosted already
        by active l3 agents.
        """
        with context.session.begin(subtransactions=True):
            # query if we have valid l3 agent on the host
            query = context.session.query(agents_db.Agent)
            query = query.filter(agents_db.Agent.agent_type ==
                                 constants.AGENT_TYPE_L3,
                                 agents_db.Agent.host == host,
                                 agents_db.Agent.admin_state_up == sql.true())
            try:
                l3_agent = query.one()
            except (exc.MultipleResultsFound, exc.NoResultFound):
                LOG.debug(_('No enabled L3 agent on host %s'),
                          host)
                return False
            if agents_db.AgentDbMixin.is_agent_down(
                l3_agent.heartbeat_timestamp):
                LOG.warn(_('L3 agent %s is not active'), l3_agent.id)
            # check if each of the specified routers is hosted
            if router_ids:
                routers = plugin.get_routers(
                    context, filters={'id': router_ids})
                unscheduled_routers = []
                for router in routers:
                    l3_agents = plugin.get_l3_agents_hosting_routers(
                        context, [router['id']], admin_state_up=True)
                    if l3_agents and not router.get('distributed', False):
                        LOG.debug(_('Router %(router_id)s has already been'
                                    ' hosted by L3 agent %(agent_id)s'),
                                  {'router_id': router['id'],
                                   'agent_id': l3_agents[0]['id']})
                    else:
                        unscheduled_routers.append(router)
                if not unscheduled_routers:
                    # all (specified) routers are already scheduled
                    return False
            else:
                # get all routers that are not hosted
                #TODO(gongysh) consider the disabled agent's router
                stmt = ~sql.exists().where(
                    l3_db.Router.id ==
                    l3_agentschedulers_db.RouterL3AgentBinding.router_id)
                unscheduled_router_ids = [router_id_[0] for router_id_ in
                                          context.session.query(
                                              l3_db.Router.id).filter(stmt)]
                if not unscheduled_router_ids:
                    LOG.debug(_('No non-hosted routers'))
                    return False
                unscheduled_routers = plugin.get_routers(
                    context, filters={'id': unscheduled_router_ids})

            # check if the configuration of l3 agent is compatible
            # with the router
            to_removed_ids = set()
            for router in unscheduled_routers:
                candidates = plugin.get_l3_agent_candidates(context,
                                                            router,
                                                            [l3_agent])
                if not candidates:
                    to_removed_ids.add(router['id'])

            target_routers = [r for r in unscheduled_routers
                              if r['id'] not in to_removed_ids]
            if not target_routers:
                LOG.warn(_('No routers compatible with L3 agent configuration'
                           ' on host %s'), host)
                return False

            for router_dict in target_routers:
                if (router_dict.get('distributed', False)
                    and self.dvr_has_binding(context,
                                             router_dict['id'],
                                             l3_agent.id)):
                    continue
                self.bind_router(context, router_dict['id'], l3_agent)
        return True

    def get_candidates(self, plugin, context, sync_router, subnet_id):
        """Return L3 agents where a router could be scheduled."""
        with context.session.begin(subtransactions=True):
            # allow one router is hosted by just
            # one enabled l3 agent hosting since active is just a
            # timing problem. Non-active l3 agent can return to
            # active any time
            l3_agents = plugin.get_l3_agents_hosting_routers(
                context, [sync_router['id']], admin_state_up=True)
            if l3_agents and not sync_router.get('distributed', False):
                LOG.debug(_('Router %(router_id)s has already been hosted'
                            ' by L3 agent %(agent_id)s'),
                          {'router_id': sync_router['id'],
                           'agent_id': l3_agents[0]['id']})
                return

            active_l3_agents = plugin.get_l3_agents(context, active=True)
            if not active_l3_agents:
                LOG.warn(_('No active L3 agents'))
                return
            new_l3agents = plugin.get_l3_agent_candidates(context,
                                                          sync_router,
                                                          active_l3_agents,
                                                          subnet_id)
            old_l3agentset = set(l3_agents)
            if sync_router.get('distributed', False):
                new_l3agentset = set(new_l3agents)
                candidates = list(new_l3agentset - old_l3agentset)
            else:
                candidates = new_l3agents
            if not candidates:
                LOG.warn(_('No L3 agents can host the router %s'),
                         sync_router['id'])
                return

            return candidates

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

        LOG.debug('Router %(router_id)s is scheduled to L3 agent '
                  '%(agent_id)s', {'router_id': router_id,
                                   'agent_id': chosen_agent.id})

    def _schedule_router(self, plugin, context, router_id,
                         candidates=None, hints=None):
        sync_router = plugin.get_router(context, router_id)
        subnet_id = hints.get('subnet_id') if hints else None
        if (hints and 'gw_exists' in hints
            and sync_router.get('distributed', False)):
            plugin.schedule_snat_router(
                context, router_id, sync_router, hints['gw_exists'])
        candidates = candidates or self.get_candidates(
            plugin, context, sync_router, subnet_id)
        if not candidates:
            return
        if sync_router.get('distributed', False):
            for chosen_agent in candidates:
                self.bind_router(context, router_id, chosen_agent)
        else:
            chosen_agent = self._choose_router_agent(
                plugin, context, candidates)
            self.bind_router(context, router_id, chosen_agent)
        return chosen_agent

    @abc.abstractmethod
    def _choose_router_agent(self, plugin, context, candidates):
        """Choose an agent from candidates based on a specific policy."""
        pass


class ChanceScheduler(L3Scheduler):
    """Randomly allocate an L3 agent for a router."""

    def schedule(self, plugin, context, router_id,
                 candidates=None, hints=None):
        with context.session.begin(subtransactions=True):
            return self._schedule_router(
                plugin, context, router_id, candidates=candidates, hints=hints)

    def _choose_router_agent(self, plugin, context, candidates):
        return random.choice(candidates)


class LeastRoutersScheduler(L3Scheduler):
    """Allocate to an L3 agent with the least number of routers bound."""

    def schedule(self, plugin, context, router_id,
                 candidates=None, hints=None):
        with context.session.begin(subtransactions=True):
            return self._schedule_router(
                plugin, context, router_id, candidates=candidates, hints=hints)

    def _choose_router_agent(self, plugin, context, candidates):
        candidate_ids = [candidate['id'] for candidate in candidates]
        chosen_agent = plugin.get_l3_agent_with_min_routers(
            context, candidate_ids)
        return chosen_agent
