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

"""service router

Revision ID: 4a666eb208c2
Revises: 38fc1f6789f8
Create Date: 2013-09-03 01:55:57.799217

"""

# revision identifiers, used by Alembic.
revision = '4a666eb208c2'
down_revision = '38fc1f6789f8'

# Change to ['*'] if this migration applies to all plugins
# This migration must apply to both NVP/NSX plugins as it alters a table
# used by both of them

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'vcns_router_bindings',
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=16), nullable=True),
        sa.Column('lswitch_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('router_id'),
        mysql_engine='InnoDB'
    )
    op.add_column(
        u'nsxrouterextattributess',
        sa.Column('service_router', sa.Boolean(), nullable=False))
    op.execute("UPDATE nsxrouterextattributess set service_router=False")


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_column(u'nsxrouterextattributess', 'service_router')
    op.drop_table('vcns_router_bindings')
