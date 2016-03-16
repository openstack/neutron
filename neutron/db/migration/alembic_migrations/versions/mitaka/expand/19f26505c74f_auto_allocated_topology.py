# Copyright 2015-2016 Hewlett Packard Enterprise Development Company, LP
#
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

""" Auto Allocated Topology - aka Get-Me-A-Network

Revision ID: 19f26505c74f
Revises: 1df244e556f5
Create Date: 2015-11-20 11:27:53.419742

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import sql

# revision identifiers, used by Alembic.
revision = '19f26505c74f'
down_revision = '1df244e556f5'


def upgrade():

    op.create_table(
        'auto_allocated_topologies',
        sa.Column('tenant_id', sa.String(length=255), primary_key=True),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='SET NULL'),
    )

    op.add_column('externalnetworks',
                  sa.Column('is_default', sa.Boolean(), nullable=False,
                            server_default=sql.false()))
