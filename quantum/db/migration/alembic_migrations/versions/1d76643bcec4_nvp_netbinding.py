# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack LLC
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

"""nvp_netbinding

Revision ID: 1d76643bcec4
Revises: 48b6f43f7471
Create Date: 2013-01-15 07:36:10.024346

"""

# revision identifiers, used by Alembic.
revision = '1d76643bcec4'
down_revision = '3cb5d900c5de'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'quantum.plugins.nicira.nicira_nvp_plugin.QuantumPlugin.NvpPluginV2'
]

from alembic import op
import sqlalchemy as sa

from quantum.db import migration


def upgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.create_table(
        'nvp_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('binding_type', sa.Enum('flat', 'vlan', 'stt', 'gre'),
                  nullable=False),
        sa.Column('tz_uuid', sa.String(length=36), nullable=True),
        sa.Column('vlan_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))


def downgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.drop_table('nvp_network_bindings')
