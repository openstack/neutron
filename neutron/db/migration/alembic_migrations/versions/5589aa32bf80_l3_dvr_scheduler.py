# Copyright 2014 OpenStack Foundation
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

"""L3 scheduler additions to support DVR

Revision ID: 5589aa32bf80
Revises: 31d7f831a591
Create Date: 2014-07-7 11:00:43.392912

"""

# revision identifiers, used by Alembic.
revision = '5589aa32bf80'
down_revision = '31d7f831a591'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'csnat_l3_agent_bindings',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('l3_agent_id', sa.String(length=36), nullable=False),
        sa.Column('host_id', sa.String(length=255), nullable=True),
        sa.Column('csnat_gw_port_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['l3_agent_id'], ['agents.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['csnat_gw_port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id')
    )
