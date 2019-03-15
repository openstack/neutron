# Copyright 2016 OpenStack Foundation
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

from collections import defaultdict

from alembic import op
import sqlalchemy as sa

"""Add binding index to RouterL3AgentBinding

Revision ID: 2e0d7a8a1586
Revises: 97c25b0d2353
Create Date: 2016-09-01 14:01:57.263289

"""

# revision identifiers, used by Alembic.
revision = '2e0d7a8a1586'
down_revision = '97c25b0d2353'


ROUTER_L3_AGENT_BINDING = 'routerl3agentbindings'


def contract_creation_exceptions():
    """Add a new binding_index to ensure that no over-creation of the bindings
    is possible.
    """
    return {
        sa.Column: ['%s.binding_index' % ROUTER_L3_AGENT_BINDING]
    }


def upgrade():
    op.add_column(ROUTER_L3_AGENT_BINDING,
                  sa.Column('binding_index', sa.Integer(), nullable=False,
                            server_default='1'))

    bindings_table = sa.Table(
        ROUTER_L3_AGENT_BINDING,
        sa.MetaData(),
        sa.Column('router_id', sa.String(36)),
        sa.Column('l3_agent_id', sa.String(36)),
        sa.Column('binding_index', sa.Integer,
                  nullable=False, server_default='1'),
    )

    routers_to_bindings = defaultdict(list)
    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        for result in session.query(bindings_table):
            routers_to_bindings[result.router_id].append(result)

        for bindings in routers_to_bindings.values():
            for index, result in enumerate(bindings):
                session.execute(bindings_table.update().values(
                    binding_index=index + 1).where(
                    bindings_table.c.router_id == result.router_id).where(
                    bindings_table.c.l3_agent_id == result.l3_agent_id))
    session.commit()

    op.create_unique_constraint(
        'uniq_router_l3_agent_binding0router_id0binding_index0',
        ROUTER_L3_AGENT_BINDING, ['router_id', 'binding_index'])
