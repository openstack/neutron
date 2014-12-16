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

"""remove mlnx plugin

Revision ID: 28c0ffb8ebbd
Revises: 408cfbf6923c
Create Date: 2014-12-08 23:58:49.288830

"""

# revision identifiers, used by Alembic.
revision = '28c0ffb8ebbd'
down_revision = '408cfbf6923c'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_table('mlnx_network_bindings')
    op.drop_table('segmentation_id_allocation')
    op.drop_table('port_profile')


def downgrade():
    op.create_table(
        'port_profile',
        sa.Column(
            'port_id', sa.String(length=36), nullable=False),
        sa.Column(
            'vnic_type', sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
    )
    op.create_table(
        'segmentation_id_allocation',
        sa.Column('physical_network',
                  sa.String(length=64),
                  nullable=False),
        sa.Column('segmentation_id',
                  sa.Integer(),
                  autoincrement=False,
                  nullable=False),
        sa.Column('allocated',
                  sa.Boolean(),
                  server_default=sa.sql.false(),
                  nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'segmentation_id')
    )
    op.create_table(
        'mlnx_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('segmentation_id',
                  sa.Integer(),
                  autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(['network_id'],
                                ['networks.id']),
        sa.PrimaryKeyConstraint('network_id'),
    )
