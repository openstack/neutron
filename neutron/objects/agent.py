# Copyright (c) 2016 Intel Corporation.
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

from neutron_lib import constants as const
from neutron_lib.objects import utils as obj_utils
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields
from sqlalchemy import func

from neutron.agent.common import utils
from neutron.db.models import agent as agent_model
from neutron.db.models import l3agent as rb_model
from neutron.db.models import l3ha as l3ha_model
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects import common_types


@base.NeutronObjectRegistry.register
class Agent(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Added resources_synced
    VERSION = '1.1'

    db_model = agent_model.Agent

    fields = {
        'id': common_types.UUIDField(),
        'agent_type': obj_fields.StringField(),
        'binary': obj_fields.StringField(),
        'topic': obj_fields.StringField(),
        'host': obj_fields.StringField(),
        'availability_zone': obj_fields.StringField(nullable=True),
        'admin_state_up': obj_fields.BooleanField(default=True),
        'started_at': obj_fields.DateTimeField(tzinfo_aware=False),
        'created_at': obj_fields.DateTimeField(tzinfo_aware=False),
        'heartbeat_timestamp': obj_fields.DateTimeField(tzinfo_aware=False),
        'description': obj_fields.StringField(nullable=True),
        'configurations': common_types.DictOfMiscValuesField(),
        'resource_versions': common_types.DictOfMiscValuesField(nullable=True),
        'load': obj_fields.IntegerField(default=0),
        'resources_synced': obj_fields.BooleanField(nullable=True),
    }

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(Agent, cls).modify_fields_to_db(fields)
        if ('configurations' in result and
                not isinstance(result['configurations'],
                               obj_utils.StringMatchingFilterObj)):
            # dump configuration into string, set '' if empty '{}'
            result['configurations'] = (
                cls.filter_to_json_str(result['configurations'], default=''))
        if ('resource_versions' in result and
                not isinstance(result['resource_versions'],
                               obj_utils.StringMatchingFilterObj)):
            # dump resource version into string, set None if empty '{}' or None
            result['resource_versions'] = (
                cls.filter_to_json_str(result['resource_versions']))
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(Agent, cls).modify_fields_from_db(db_obj)
        if 'configurations' in fields:
            # load string from DB, set {} if configuration is ''
            fields['configurations'] = (
                cls.load_json_from_str(fields['configurations'], default={}))
        if 'resource_versions' in fields:
            # load string from DB, set None if resource_version is None or ''
            fields['resource_versions'] = (
                cls.load_json_from_str(fields['resource_versions']))
        return fields

    def obj_make_compatible(self, primitive, target_version):
        super(Agent, self).obj_make_compatible(primitive, target_version)
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            primitive.pop('resources_synced', None)

    @property
    def is_active(self):
        return not utils.is_agent_down(self.heartbeat_timestamp)

    # TODO(ihrachys) reuse query builder from
    # get_l3_agents_ordered_by_num_routers
    @classmethod
    def get_l3_agent_with_min_routers(cls, context, agent_ids):
        """Return l3 agent with the least number of routers."""
        with cls.db_context_reader(context):
            query = context.session.query(
                agent_model.Agent,
                func.count(
                    rb_model.RouterL3AgentBinding.router_id
                ).label('count')).outerjoin(
                    rb_model.RouterL3AgentBinding).group_by(
                    agent_model.Agent.id,
                    rb_model.RouterL3AgentBinding
                    .l3_agent_id).order_by('count')
            res = query.filter(agent_model.Agent.id.in_(agent_ids)).first()
        agent_obj = cls._load_object(context, res[0])
        return agent_obj

    @classmethod
    def get_l3_agents_ordered_by_num_routers(cls, context, agent_ids):
        with cls.db_context_reader(context):
            query = (context.session.query(agent_model.Agent, func.count(
                rb_model.RouterL3AgentBinding.router_id)
                .label('count')).
                outerjoin(rb_model.RouterL3AgentBinding).
                group_by(agent_model.Agent.id).
                filter(agent_model.Agent.id.in_(agent_ids)).
                order_by('count'))
        agents = [cls._load_object(context, record[0]) for record in query]

        return agents

    @classmethod
    def get_ha_agents(cls, context, network_id=None, router_id=None):
        if not (network_id or router_id):
            return []
        query = context.session.query(agent_model.Agent.host)
        query = query.join(l3ha_model.L3HARouterAgentPortBinding,
                           l3ha_model.L3HARouterAgentPortBinding.l3_agent_id ==
                           agent_model.Agent.id)
        if router_id:
            query = query.filter(
                l3ha_model.L3HARouterAgentPortBinding.router_id ==
                router_id).all()
        elif network_id:
            query = query.join(models_v2.Port, models_v2.Port.device_id ==
                               l3ha_model.L3HARouterAgentPortBinding.router_id)
            query = query.filter(models_v2.Port.network_id == network_id,
                                 models_v2.Port.status ==
                                 const.PORT_STATUS_ACTIVE,
                                 models_v2.Port.device_owner.in_(
                                     (const.DEVICE_OWNER_HA_REPLICATED_INT,
                                      const.DEVICE_OWNER_ROUTER_SNAT))).all()
        # L3HARouterAgentPortBinding will have l3 agent ids of hosting agents.
        # But we need l2 agent(for tunneling ip) while creating FDB entries.
        hosts = [host[0] for host in query]
        agents = cls.get_objects(context, host=hosts)
        return agents

    @classmethod
    def _get_agents_by_availability_zones_and_agent_type(
            cls, context, agent_type, availability_zones):
        query = context.session.query(
            agent_model.Agent).filter_by(
            agent_type=agent_type).group_by(
            agent_model.Agent.availability_zone)
        query = query.filter(
            agent_model.Agent.availability_zone.in_(availability_zones)).all()
        agents = [cls._load_object(context, record) for record in query]
        return agents

    @classmethod
    def get_objects_by_agent_mode(cls, context, agent_mode=None, **kwargs):
        mode_filter = obj_utils.StringContains(agent_mode)
        return cls.get_objects(context, configurations=mode_filter, **kwargs)
