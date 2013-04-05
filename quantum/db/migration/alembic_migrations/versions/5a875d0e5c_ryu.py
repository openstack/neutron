# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 New Dream Network, LLC (DreamHost)
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
# @author: Mark McClain, DreamHost

"""ryu

This retroactively provides migration support for
https://review.openstack.org/#/c/11204/

Revision ID: 5a875d0e5c
Revises: 2c4af419145b
Create Date: 2012-12-18 12:32:04.482477

"""


# revision identifiers, used by Alembic.
revision = '5a875d0e5c'
down_revision = '2c4af419145b'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'quantum.plugins.ryu.ryu_quantum_plugin.RyuQuantumPluginV2'
]

from alembic import op
import sqlalchemy as sa

from quantum.db import migration


def upgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.create_table(
        'tunnelkeys',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('last_key', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('last_key')
    )

    op.create_table(
        'tunnelkeylasts',
        sa.Column('last_key', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.PrimaryKeyConstraint('last_key')
    )


def downgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.drop_table('tunnelkeylasts')
    op.drop_table('tunnelkeys')
