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

# Initial operations for Nuage plugin

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'nuage_net_partitions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=True),
        sa.Column('l3dom_tmplt_id', sa.String(length=36), nullable=True),
        sa.Column('l2dom_tmplt_id', sa.String(length=36), nullable=True),
        sa.Column('isolated_zone', sa.String(length=64), nullable=True),
        sa.Column('shared_zone', sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'nuage_subnet_l2dom_mapping',
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('net_partition_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_subnet_id', sa.String(length=36), nullable=True,
                  unique=True),
        sa.Column('nuage_l2dom_tmplt_id', sa.String(length=36),
                  nullable=True),
        sa.Column('nuage_user_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_group_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_managed_subnet', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['net_partition_id'],
                                ['nuage_net_partitions.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subnet_id'),
    )
    op.create_table(
        'nuage_net_partition_router_mapping',
        sa.Column('net_partition_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('nuage_router_id', sa.String(length=36), nullable=True,
                  unique=True),
        sa.Column('nuage_rtr_rd', sa.String(length=36), nullable=True),
        sa.Column('nuage_rtr_rt', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['net_partition_id'],
                                ['nuage_net_partitions.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('net_partition_id', 'router_id'),
    )
    op.create_table(
        'nuage_provider_net_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ['network_id'], ['networks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )
