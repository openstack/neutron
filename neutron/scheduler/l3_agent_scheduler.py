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

import abc
import random

import six
from sqlalchemy.orm import exc
from sqlalchemy.sql import exists

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class L3Scheduler(object):

    @abc.abstractmethod
    def schedule(self, plugin, context, router_id):
        """Schedule the router to an active L3 agent.

        Schedule the router only if it is not already scheduled.
        """
        pass

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
                                 agents_db.Agent.admin_state_up == True)
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
                unscheduled_router_ids = []
                for router_id in router_ids:
                    l3_agents = plugin.get_l3_agents_hosting_routers(
                        context, [router_id], admin_state_up=True)
                    if l3_agents:
                        LOG.debug(_('Router %(router_id)s has already been'
                                    ' hosted by L3 agent %(agent_id)s'),
                                  {'router_id': router_id,
                                   'agent_id': l3_agents[0]['id']})
                    else:
                        unscheduled_router_ids.append(router_id)
                if not unscheduled_router_ids:
                    # all (specified) routers are already scheduled
                    return False
            else:
                # get all routers that are not hosted
                #TODO(gongysh) consider the disabled agent's router
                stmt = ~exists().where(
                    l3_db.Router.id ==
                    l3_agentschedulers_db.RouterL3AgentBinding.router_id)
                unscheduled_router_ids = [router_id_[0] for router_id_ in
                                          context.session.query(
                                              l3_db.Router.id).filter(stmt)]
                if not unscheduled_router_ids:
                    LOG.debug(_('No non-hosted routers'))
                    return False

            # check if the configuration of l3 agent is compatible
            # with the router
            routers = plugin.get_routers(
                context, filters={'id': unscheduled_router_ids})
            to_removed_ids = []
            for router in routers:
                candidates = plugin.get_l3_agent_candidates(router, [l3_agent])
                if not candidates:
                    to_removed_ids.append(router['id'])
            router_ids = set([r['id'] for r in routers]) - set(to_removed_ids)
            if not router_ids:
                LOG.warn(_('No routers compatible with L3 agent configuration'
                           ' on host %s'), host)
                return False

            for router_id in router_ids:
                self.bind_router(context, router_id, l3_agent)
        return True

    def get_candidates(self, plugin, context, sync_router):
        """Return L3 agents where a router could be scheduled."""
        with context.session.begin(subtransactions=True):
            # allow one router is hosted by just
            # one enabled l3 agent hosting since active is just a
            # timing problem. Non-active l3 agent can return to
            # active any time
            l3_agents = plugin.get_l3_agents_hosting_routers(
                context, [sync_router['id']], admin_state_up=True)
            if l3_agents:
                LOG.debug(_('Router %(router_id)s has already been hosted'
                            ' by L3 agent %(agent_id)s'),
                          {'router_id': sync_router['id'],
                           'agent_id': l3_agents[0]['id']})
                return

            active_l3_agents = plugin.get_l3_agents(context, active=True)
            if not active_l3_agents:
                LOG.warn(_('No active L3 agents'))
                return
            candidates = plugin.get_l3_agent_candidates(sync_router,
                                                        active_l3_agents)
            if not candidates:
                LOG.warn(_('No L3 agents can host the router %s'),
                         sync_router['id'])
                return

            return candidates

    def bind_router(self, context, router_id, chosen_agent):
        """Bind the router to the l3 agent which has been chosen."""
        with context.session.begin(subtransactions=True):
            binding = l3_agentschedulers_db.RouterL3AgentBinding()
            binding.l3_agent = chosen_agent
            binding.router_id = router_id
            context.session.add(binding)
            LOG.debug(_('Router %(router_id)s is scheduled to '
                        'L3 agent %(agent_id)s'),
                      {'router_id': router_id,
                       'agent_id': chosen_agent.id})


class ChanceScheduler(L3Scheduler):
    """Randomly allocate an L3 agent for a router."""

    def schedule(self, plugin, context, router_id):
        with context.session.begin(subtransactions=True):
            sync_router = plugin.get_router(context, router_id)
            candidates = self.get_candidates(plugin, context, sync_router)
            if not candidates:
                return

            chosen_agent = random.choice(candidates)
            self.bind_router(context, router_id, chosen_agent)
            return chosen_agent


class LeastRoutersScheduler(L3Scheduler):
    """Allocate to an L3 agent with the least number of routers bound."""

    def schedule(self, plugin, context, router_id):
        with context.session.begin(subtransactions=True):
            sync_router = plugin.get_router(context, router_id)
            candidates = self.get_candidates(plugin, context, sync_router)
            if not candidates:
                return

            candidate_ids = [candidate['id'] for candidate in candidates]
            chosen_agent = plugin.get_l3_agent_with_min_routers(
                context, candidate_ids)

            self.bind_router(context, router_id, chosen_agent)

            return chosen_agent
