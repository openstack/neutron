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

"""nvp_portmap

Revision ID: 38335592a0dc
Revises: 49332180ca96
Create Date: 2013-01-15 06:04:56.328991

"""

# revision identifiers, used by Alembic.
revision = '38335592a0dc'
down_revision = '49332180ca96'

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
        'quantum_nvp_port_mapping',
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.Column('nvp_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['quantum_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('quantum_id'))


def downgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.drop_table('quantum_nvp_port_mapping')
