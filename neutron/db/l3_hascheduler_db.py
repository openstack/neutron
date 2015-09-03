# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from sqlalchemy import func
from sqlalchemy import sql

from neutron.db import agents_db
from neutron.db import l3_agentschedulers_db as l3_sch_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db


class L3_HA_scheduler_db_mixin(l3_sch_db.L3AgentSchedulerDbMixin):

    def get_ha_routers_l3_agents_count(self, context):
        """Return a map between HA routers and how many agents every
        router is scheduled to.
        """

        # Postgres requires every column in the select to be present in
        # the group by statement when using an aggregate function.
        # One solution is to generate a subquery and join it with the desired
        # columns.
        binding_model = l3_sch_db.RouterL3AgentBinding
        sub_query = (context.session.query(
            binding_model.router_id,
            func.count(binding_model.router_id).label('count')).
            join(l3_attrs_db.RouterExtraAttributes,
                 binding_model.router_id ==
                 l3_attrs_db.RouterExtraAttributes.router_id).
            join(l3_db.Router).
            filter(l3_attrs_db.RouterExtraAttributes.ha == sql.true()).
            group_by(binding_model.router_id).subquery())

        query = (context.session.query(
                 l3_db.Router.id, l3_db.Router.tenant_id, sub_query.c.count).
                 join(sub_query))
        return query

    def get_l3_agents_ordered_by_num_routers(self, context, agent_ids):
        if not agent_ids:
            return []
        query = (context.session.query(agents_db.Agent, func.count(
            l3_sch_db.RouterL3AgentBinding.router_id).label('count')).
            outerjoin(l3_sch_db.RouterL3AgentBinding).
            group_by(agents_db.Agent.id).
            filter(agents_db.Agent.id.in_(agent_ids)).
            order_by('count'))

        return [record[0] for record in query]

    def _get_agents_dict_for_router(self, agents_and_states):
        agents = []
        for agent, ha_state in agents_and_states:
            l3_agent_dict = self._make_agent_dict(agent)
            l3_agent_dict['ha_state'] = ha_state
            agents.append(l3_agent_dict)
        return {'agents': agents}

    def list_l3_agents_hosting_router(self, context, router_id):
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, router_id)
            if router_db.extra_attributes.ha:
                bindings = self.get_l3_bindings_hosting_router_with_ha_states(
                    context, router_id)
            else:
                bindings = self._get_l3_bindings_hosting_routers(
                    context, [router_id])
                bindings = [(binding.l3_agent, None) for binding in bindings]

        return self._get_agents_dict_for_router(bindings)
