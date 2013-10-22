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

"""metering

Revision ID: 569e98a8132b
Revises: 13de305df56e
Create Date: 2013-07-17 15:38:36.254595

"""

# revision identifiers, used by Alembic.
revision = '569e98a8132b'
down_revision = 'f9263d6df56'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['neutron.services.metering.metering_plugin.'
                         'MeteringPlugin']

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

meteringlabels_direction = sa.Enum('ingress', 'egress',
                                   name='meteringlabels_direction')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('meteringlabelrules')
    meteringlabels_direction.drop(op.get_bind(), checkfirst=False)
    op.drop_table('meteringlabels')


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table('meteringlabels',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('name', sa.String(length=255),
                              nullable=True),
                    sa.Column('description', sa.String(length=1024),
                              nullable=True),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('meteringlabelrules',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('direction', meteringlabels_direction,
                              nullable=True),
                    sa.Column('remote_ip_prefix', sa.String(length=64),
                              nullable=True),
                    sa.Column('metering_label_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('excluded', sa.Boolean(),
                              autoincrement=False, nullable=True),
                    sa.ForeignKeyConstraint(['metering_label_id'],
                                            ['meteringlabels.id'],
                                            name='meteringlabelrules_ibfk_1'),
                    sa.PrimaryKeyConstraint('id'))
