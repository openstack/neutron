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
#

from neutron_lib import constants as n_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import agent as agent_model
from neutron.db import models_v2


class L3HARouterAgentPortBinding(model_base.BASEV2):
    """Represent agent binding state of a HA router port.

    A HA Router has one HA port per agent on which it is spawned.
    This binding table stores which port is used for a HA router by a
    L3 agent.
    """

    __tablename__ = 'ha_router_agent_port_bindings'
    __table_args__ = (
        sa.UniqueConstraint(
            'router_id', 'l3_agent_id',
            name='uniq_ha_router_agent_port_bindings0port_id0l3_agent_id'),
        model_base.BASEV2.__table_args__
    )
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                                                     ondelete='CASCADE'),
                        nullable=False, primary_key=True)
    port = orm.relationship(models_v2.Port, lazy='joined')

    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id',
                                                       ondelete='CASCADE'),
                          nullable=False)

    l3_agent_id = sa.Column(sa.String(36),
                            sa.ForeignKey("agents.id",
                                          ondelete='CASCADE'))
    agent = orm.relationship(agent_model.Agent, lazy='joined')

    state = sa.Column(sa.Enum(n_const.HA_ROUTER_STATE_ACTIVE,
                              n_const.HA_ROUTER_STATE_STANDBY,
                              n_const.HA_ROUTER_STATE_UNKNOWN,
                              name='l3_ha_states'),
                      default=n_const.HA_ROUTER_STATE_STANDBY,
                      server_default=n_const.HA_ROUTER_STATE_STANDBY)


class L3HARouterNetwork(model_base.BASEV2, model_base.HasProjectPrimaryKey):
    """Host HA network for a tenant.

    One HA Network is used per tenant, all HA router ports are created
    on this network.
    """

    __tablename__ = 'ha_router_networks'
    __table_args__ = (
        sa.UniqueConstraint('project_id',
                            name='uniq_ha_router_networks0project_id'),
        model_base.BASEV2.__table_args__
    )

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False, primary_key=True)
    network = orm.relationship(models_v2.Network)


class L3HARouterVRIdAllocation(model_base.BASEV2):
    """VRID allocation per HA network.

    Keep a track of the VRID allocations per HA network.
    """

    __tablename__ = 'ha_router_vrid_allocations'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False, primary_key=True)
    vr_id = sa.Column(sa.Integer(), nullable=False, primary_key=True)
