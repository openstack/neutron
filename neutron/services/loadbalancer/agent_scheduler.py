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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import joinedload

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import model_base
from neutron.extensions import lbaas_agentscheduler
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class PoolLoadbalancerAgentBinding(model_base.BASEV2):
    """Represents binding between neutron loadbalancer pools and agents."""

    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("pools.id", ondelete='CASCADE'),
                        primary_key=True)
    agent = orm.relation(agents_db.Agent)
    agent_id = sa.Column(sa.String(36), sa.ForeignKey("agents.id",
                                                      ondelete='CASCADE'))


class LbaasAgentSchedulerDbMixin(agentschedulers_db.AgentSchedulerDbMixin,
                                 lbaas_agentscheduler
                                 .LbaasAgentSchedulerPluginBase):

    def get_lbaas_agent_hosting_pool(self, context, pool_id, active=None):
        query = context.session.query(PoolLoadbalancerAgentBinding)
        query = query.options(joinedload('agent'))
        binding = query.get(pool_id)

        if (binding and self.is_eligible_agent(
                active, binding.agent)):
            return {'agent': self._make_agent_dict(binding.agent)}

    def get_lbaas_agents(self, context, active=None, filters=None):
        query = context.session.query(agents_db.Agent)
        query = query.filter_by(agent_type=constants.AGENT_TYPE_LOADBALANCER)
        if active is not None:
            query = query.filter_by(admin_state_up=active)
        if filters:
            for key, value in filters.iteritems():
                column = getattr(agents_db.Agent, key, None)
                if column:
                    query = query.filter(column.in_(value))

        return [agent
                for agent in query
                if self.is_eligible_agent(active, agent)]

    def list_pools_on_lbaas_agent(self, context, id):
        query = context.session.query(PoolLoadbalancerAgentBinding.pool_id)
        query = query.filter_by(agent_id=id)
        pool_ids = [item[0] for item in query]
        if pool_ids:
            return {'pools': self.get_pools(context, filters={'id': pool_ids})}
        else:
            return {'pools': []}


class ChanceScheduler(object):
    """Allocate a loadbalancer agent for a vip in a random way."""

    def schedule(self, plugin, context, pool):
        """Schedule the pool to an active loadbalancer agent if there
        is no enabled agent hosting it.
        """
        with context.session.begin(subtransactions=True):
            lbaas_agent = plugin.get_lbaas_agent_hosting_pool(
                context, pool['id'])
            if lbaas_agent:
                LOG.debug(_('Pool %(pool_id)s has already been hosted'
                            ' by lbaas agent %(agent_id)s'),
                          {'pool_id': pool['id'],
                           'agent_id': lbaas_agent['id']})
                return

            candidates = plugin.get_lbaas_agents(context, active=True)
            if not candidates:
                LOG.warn(_('No active lbaas agents for pool %s') % pool['id'])
                return

            chosen_agent = random.choice(candidates)
            binding = PoolLoadbalancerAgentBinding()
            binding.agent = chosen_agent
            binding.pool_id = pool['id']
            context.session.add(binding)
            LOG.debug(_('Pool %(pool_id)s is scheduled to '
                        'lbaas agent %(agent_id)s'),
                      {'pool_id': pool['id'],
                       'agent_id': chosen_agent['id']})
            return chosen_agent
