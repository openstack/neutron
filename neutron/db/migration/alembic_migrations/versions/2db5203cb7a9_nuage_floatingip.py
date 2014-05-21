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

"""nuage_floatingip

Revision ID: 2db5203cb7a9
Revises: 10cd28e692e9
Create Date: 2014-05-19 16:39:42.048125

"""

# revision identifiers, used by Alembic.
revision = '2db5203cb7a9'
down_revision = '10cd28e692e9'

migration_for_plugins = [
    'neutron.plugins.nuage.plugin.NuagePlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'nuage_floatingip_pool_mapping',
        sa.Column('fip_pool_id', sa.String(length=36), nullable=False),
        sa.Column('net_id', sa.String(length=36), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['net_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('fip_pool_id'),
    )
    op.create_table(
        'nuage_floatingip_mapping',
        sa.Column('fip_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.Column('nuage_fip_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['fip_id'], ['floatingips.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('fip_id'),
    )
    op.rename_table('net_partitions', 'nuage_net_partitions')
    op.rename_table('net_partition_router_mapping',
                    'nuage_net_partition_router_mapping')
    op.rename_table('router_zone_mapping', 'nuage_router_zone_mapping')
    op.rename_table('subnet_l2dom_mapping', 'nuage_subnet_l2dom_mapping')
    op.rename_table('port_mapping', 'nuage_port_mapping')
    op.rename_table('routerroutes_mapping', 'nuage_routerroutes_mapping')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('nuage_floatingip_mapping')
    op.drop_table('nuage_floatingip_pool_mapping')
    op.rename_table('nuage_net_partitions', 'net_partitions')
    op.rename_table('nuage_net_partition_router_mapping',
                    'net_partition_router_mapping')
    op.rename_table('nuage_router_zone_mapping', 'router_zone_mapping')
    op.rename_table('nuage_subnet_l2dom_mapping', 'subnet_l2dom_mapping')
    op.rename_table('nuage_port_mapping', 'port_mapping')
    op.rename_table('nuage_routerroutes_mapping', 'routerroutes_mapping')
