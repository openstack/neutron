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

import random

from sqlalchemy.orm import exc
from sqlalchemy.sql import exists

from quantum.common import constants
from quantum.db import l3_db
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class ChanceScheduler(object):
    """Allocate a L3 agent for a router in a random way.
    More sophisticated scheduler (similar to filter scheduler in nova?)
    can be introduced later."""

    def auto_schedule_routers(self, plugin, context, host, router_id):
        """Schedule non-hosted routers to L3 Agent running on host.
        If router_id is given, only this router is scheduled
        if it is not hosted yet.
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
            # check if the specified router is hosted
            if router_id:
                l3_agents = plugin.get_l3_agents_hosting_routers(
                    context, [router_id], admin_state_up=True)
                if l3_agents:
                    LOG.debug(_('Router %(router_id)s has already been hosted'
                                ' by L3 agent %(agent_id)s'),
                              {'router_id': router_id,
                               'agent_id': l3_agents[0]['id']})
                    return False

            # get the router ids
            if router_id:
                router_ids = [(router_id,)]
            else:
                # get all routers that are not hosted
                #TODO(gongysh) consider the disabled agent's router
                stmt = ~exists().where(
                    l3_db.Router.id ==
                    agentschedulers_db.RouterL3AgentBinding.router_id)
                router_ids = context.session.query(
                    l3_db.Router.id).filter(stmt).all()
            if not router_ids:
                LOG.debug(_('No non-hosted routers'))
                return False

            # check if the configuration of l3 agent is compatible
            # with the router
            router_ids = [router_id_[0] for router_id_ in router_ids]
            routers = plugin.get_routers(context, filters={'id': router_ids})
            to_removed_ids = []
            for router in routers:
                candidates = plugin.get_l3_agent_candidates(router, [l3_agent])
                if not candidates:
                    to_removed_ids.append(router['id'])
            router_ids = list(set(router_ids) - set(to_removed_ids))
            if not router_ids:
                LOG.warn(_('No routers compatible with L3 agent configuration'
                           ' on host %s'), host)
                return False

            # binding
            for router_id in router_ids:
                binding = agentschedulers_db.RouterL3AgentBinding()
                binding.l3_agent = l3_agent
                binding.router_id = router_id
                binding.default = True
                context.session.add(binding)
        return True

    def schedule(self, plugin, context, sync_router):
        """Schedule the router to an active L3 agent if there
        is no enable L3 agent hosting it.
        """
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

            chosen_agent = random.choice(candidates)
            binding = agentschedulers_db.RouterL3AgentBinding()
            binding.l3_agent = chosen_agent
            binding.router_id = sync_router['id']
            context.session.add(binding)
            LOG.debug(_('Router %(router_id)s is scheduled to '
                        'L3 agent %(agent_id)s'),
                      {'router_id': sync_router['id'],
                       'agent_id': chosen_agent['id']})
            return chosen_agent
