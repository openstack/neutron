# Copyright 2015 OpenStack Foundation
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
#

"""DVR sheduling refactoring

Revision ID: 2b4c2465d44b
Revises: 8a6d8bdae39
Create Date: 2015-12-23 07:39:49.062767

"""

# revision identifiers, used by Alembic.
revision = '2b4c2465d44b'
down_revision = '8a6d8bdae39'

from alembic import op
import sqlalchemy as sa


ROUTER_ATTR_TABLE = 'router_extra_attributes'
ROUTER_BINDING_TABLE = 'routerl3agentbindings'
CSNAT_BINDING_TABLE = 'csnat_l3_agent_bindings'


def upgrade():
    transfer_snat_bindings()
    op.drop_table(CSNAT_BINDING_TABLE)


def transfer_snat_bindings():
    router_attr_table = sa.Table(ROUTER_ATTR_TABLE,
                                 sa.MetaData(),
                                 sa.Column('router_id', sa.String(36)),
                                 sa.Column('distributed', sa.Boolean),)

    csnat_binding = sa.Table(CSNAT_BINDING_TABLE,
                             sa.MetaData(),
                             sa.Column('router_id', sa.String(36)),
                             sa.Column('l3_agent_id', sa.String(36)))

    router_binding = sa.Table(ROUTER_BINDING_TABLE,
                              sa.MetaData(),
                              sa.Column('router_id', sa.String(36)),
                              sa.Column('l3_agent_id', sa.String(36)))

    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        # first delete all bindings for dvr routers from
        # routerl3agentbindings as this might be bindings with l3 agents
        # on compute nodes
        for router_attr in session.query(
                router_attr_table).filter(router_attr_table.c.distributed):
            session.execute(router_binding.delete(
                router_binding.c.router_id == router_attr.router_id))

        # now routerl3agentbindings will only contain bindings for snat
        # portion of the router
        for csnat_binding in session.query(csnat_binding):
            session.execute(
                router_binding.insert().values(
                    router_id=csnat_binding.router_id,
                    l3_agent_id=csnat_binding.l3_agent_id))
    # this commit is necessary to allow further operations
    session.commit()
