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

"""NEC plugin sharednet

Revision ID: 3b54bf9e29f7
Revises: 511471cc46b
Create Date: 2013-02-17 09:21:48.287134

"""

# revision identifiers, used by Alembic.
revision = '3b54bf9e29f7'
down_revision = '511471cc46b'

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
        'ofctenantmappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id')
    )
    op.create_table(
        'ofcnetworkmappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id')
    )
    op.create_table(
        'ofcportmappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id')
    )
    op.create_table(
        'ofcfiltermappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('ofcfiltermappings')
    op.drop_table('ofcportmappings')
    op.drop_table('ofcnetworkmappings')
    op.drop_table('ofctenantmappings')
