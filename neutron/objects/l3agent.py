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

from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields
import sqlalchemy as sa
from sqlalchemy.orm import joinedload

from sqlalchemy import sql

from neutron.common import _constants as n_const
from neutron.db.models import agent as agent_model
from neutron.db.models import l3_attrs
from neutron.db.models import l3agent
from neutron.objects import base


@base.NeutronObjectRegistry.register
class RouterL3AgentBinding(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3agent.RouterL3AgentBinding

    primary_keys = ['router_id', 'l3_agent_id']

    fields = {
        'router_id': common_types.UUIDField(),
        'l3_agent_id': common_types.UUIDField(),
        'binding_index': obj_fields.IntegerField(
            default=n_const.LOWEST_AGENT_BINDING_INDEX),
    }

    # TODO(ihrachys) return OVO objects not models
    # TODO(ihrachys) move under Agent object class
    @classmethod
    def get_l3_agents_by_router_ids(cls, context, router_ids):
        query = context.session.query(l3agent.RouterL3AgentBinding)
        query = query.options(joinedload('l3_agent')).filter(
            l3agent.RouterL3AgentBinding.router_id.in_(router_ids))
        return [db_obj.l3_agent for db_obj in query.all()]

    @classmethod
    def get_down_router_bindings(cls, context, cutoff):
        query = (context.session.query(
                 l3agent.RouterL3AgentBinding).
                 join(agent_model.Agent).
                 filter(agent_model.Agent.heartbeat_timestamp < cutoff,
                 agent_model.Agent.admin_state_up).outerjoin(
                     l3_attrs.RouterExtraAttributes,
                     l3_attrs.RouterExtraAttributes.router_id ==
                 l3agent.RouterL3AgentBinding.router_id).filter(
                 sa.or_(
                     l3_attrs.RouterExtraAttributes.ha == sql.false(),
                     l3_attrs.RouterExtraAttributes.ha == sql.null())))
        bindings = [cls._load_object(context, db_obj) for db_obj in
                    query.all()]
        return bindings
