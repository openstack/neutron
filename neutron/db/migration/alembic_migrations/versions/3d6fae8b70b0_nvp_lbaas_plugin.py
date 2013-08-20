# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation
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

"""nvp lbaas plugin

Revision ID: 3d6fae8b70b0
Revises: 3ed8f075e38a
Create Date: 2013-09-13 19:34:41.522665

"""

# revision identifiers, used by Alembic.
revision = '3d6fae8b70b0'
down_revision = '3ed8f075e38a'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'vcns_edge_pool_bindings',
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('pool_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('pool_id', 'edge_id')
    )
    op.create_table(
        'vcns_edge_monitor_bindings',
        sa.Column('monitor_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('monitor_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['monitor_id'], ['healthmonitors.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('monitor_id', 'edge_id')
    )
    op.create_table(
        'vcns_edge_vip_bindings',
        sa.Column('vip_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=True),
        sa.Column('vip_vseid', sa.String(length=36), nullable=True),
        sa.Column('app_profileid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['vip_id'], ['vips.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('vip_id')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('vcns_edge_vip_bindings')
    op.drop_table('vcns_edge_monitor_bindings')
    op.drop_table('vcns_edge_pool_bindings')
