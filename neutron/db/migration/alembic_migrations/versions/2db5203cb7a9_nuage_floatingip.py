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


from alembic import op
import sqlalchemy as sa

from neutron.db import migration

# This migration will be executed only if the neutron DB schema contains
# the tables for the nuage plugin.
# This migration will be skipped when executed in offline mode.


@migration.skip_if_offline
def upgrade():
    # These tables will be created even if the nuage plugin is not enabled.
    # This is fine as they would be created anyway by the healing migration.
    if migration.schema_has_table('routers'):
        # In the database we are migrating from, the configured plugin
        # did not create the routers table.
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
    if migration.schema_has_table('floatingips'):
        # In the database we are migrating from, the configured plugin
        # did not create the floatingips table.
        op.create_table(
            'nuage_floatingip_mapping',
            sa.Column('fip_id', sa.String(length=36), nullable=False),
            sa.Column('router_id', sa.String(length=36), nullable=True),
            sa.Column('nuage_fip_id', sa.String(length=36), nullable=True),
            sa.ForeignKeyConstraint(['fip_id'], ['floatingips.id'],
                                    ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('fip_id'),
        )
    migration.rename_table_if_exists('net_partitions',
                                     'nuage_net_partitions')
    migration.rename_table_if_exists('net_partition_router_mapping',
                                     'nuage_net_partition_router_mapping')
    migration.rename_table_if_exists('router_zone_mapping',
                                     'nuage_router_zone_mapping')
    migration.rename_table_if_exists('subnet_l2dom_mapping',
                                     'nuage_subnet_l2dom_mapping')
    migration.rename_table_if_exists('port_mapping',
                                     'nuage_port_mapping')
    migration.rename_table_if_exists('routerroutes_mapping',
                                     'nuage_routerroutes_mapping')
