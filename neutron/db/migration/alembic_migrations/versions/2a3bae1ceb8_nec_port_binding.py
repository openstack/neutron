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

"""NEC Port Binding

Revision ID: 2a3bae1ceb8
Revises: 46a0efbd8f0
Create Date: 2013-08-22 11:09:19.955386

"""

# revision identifiers, used by Alembic.
revision = '2a3bae1ceb8'
down_revision = '46a0efbd8f0'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nec.nec_plugin.NECPluginV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'portbindingports',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id')
    )
    op.create_foreign_key(
        'portinfos_ibfk_1',
        source='portinfos', referent='ports',
        local_cols=['id'], remote_cols=['id'],
        ondelete='CASCADE')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_constraint('portinfos_ibfk_1', 'portinfos', 'foreignkey')
    op.drop_table('portbindingports')
