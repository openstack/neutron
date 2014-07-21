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

"""Remove cisco_vlan_bindings table

Revision ID: b7a8863760e
Revises: 3cabb850f4a5
Create Date: 2013-07-03 19:15:19.143175

"""

# revision identifiers, used by Alembic.
revision = 'b7a8863760e'
down_revision = '3cabb850f4a5'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.cisco.network_plugin.PluginV2'
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('cisco_vlan_bindings')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'cisco_vlan_bindings',
        sa.Column('vlan_id', sa.Integer(), nullable=False),
        sa.Column('vlan_name', sa.String(length=255), nullable=True),
        sa.Column('network_id', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('vlan_id')
    )
