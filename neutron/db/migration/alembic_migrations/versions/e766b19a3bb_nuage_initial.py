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

"""nuage_initial

Revision ID: e766b19a3bb
Revises: 1b2580001654
Create Date: 2014-02-14 18:03:14.841064

"""

# revision identifiers, used by Alembic.
revision = 'e766b19a3bb'
down_revision = '1b2580001654'

migration_for_plugins = [
    'neutron.plugins.nuage.plugin.NuagePlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration
from neutron.db.migration.alembic_migrations import common_ext_ops


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    common_ext_ops.upgrade_l3()

    op.create_table(
        'quotas',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('resource', sa.String(length=255), nullable=True),
        sa.Column('limit', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'net_partitions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=True),
        sa.Column('l3dom_tmplt_id', sa.String(length=36), nullable=True),
        sa.Column('l2dom_tmplt_id', sa.String(length=36), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'port_mapping',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('nuage_vport_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_vif_id', sa.String(length=36), nullable=True),
        sa.Column('static_ip', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
    )
    op.create_table(
        'subnet_l2dom_mapping',
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('net_partition_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_subnet_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_l2dom_tmplt_id', sa.String(length=36),
                  nullable=True),
        sa.Column('nuage_user_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_group_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['net_partition_id'], ['net_partitions.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subnet_id'),
    )
    op.create_table(
        'net_partition_router_mapping',
        sa.Column('net_partition_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('nuage_router_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['net_partition_id'], ['net_partitions.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'),
    )
    op.create_table(
        'router_zone_mapping',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('nuage_zone_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_user_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_group_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'),
    )


def downgrade(active_plugins=None, options=None):
    pass