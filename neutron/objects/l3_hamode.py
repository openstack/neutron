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

from neutron_lib import constants
from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import agent as agent_model
from neutron.db.models import l3ha
from neutron.objects import base


@base.NeutronObjectRegistry.register
class L3HARouterAgentPortBinding(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3ha.L3HARouterAgentPortBinding

    fields = {
        'port_id': common_types.UUIDField(),
        'router_id': common_types.UUIDField(),
        'l3_agent_id': common_types.UUIDField(nullable=True),
        'state': common_types.HARouterEnumField(
            default=constants.HA_ROUTER_STATE_STANDBY),
    }

    primary_keys = ['port_id']
    fields_no_update = ['router_id', 'port_id']

    @classmethod
    def get_l3ha_filter_host_router(cls, context, router_ids, host):
        query = context.session.query(l3ha.L3HARouterAgentPortBinding)

        if host:
            query = query.join(agent_model.Agent).filter(
                agent_model.Agent.host == host)

        query = query.filter(
            l3ha.L3HARouterAgentPortBinding.router_id.in_(router_ids))
        return query.all()


@base.NeutronObjectRegistry.register
class L3HARouterNetwork(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3ha.L3HARouterNetwork

    fields = {
        'network_id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(),
    }

    primary_keys = ['network_id', 'project_id']


@base.NeutronObjectRegistry.register
class L3HARouterVRIdAllocation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3ha.L3HARouterVRIdAllocation

    fields = {
        'network_id': common_types.UUIDField(),
        'vr_id': obj_fields.IntegerField()
    }

    primary_keys = ['network_id', 'vr_id']
