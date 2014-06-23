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

"""remove bigswitch port tracking table

Revision ID: 86cf4d88bd3
Revises: 569e98a8132b
Create Date: 2013-08-13 21:59:04.373496

"""

# revision identifiers, used by Alembic.
revision = '86cf4d88bd3'
down_revision = '569e98a8132b'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.bigswitch.plugin.NeutronRestProxyV2'
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('portlocations')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table('portlocations',
                    sa.Column('port_id', sa.String(length=255),
                              primary_key=True, nullable=False),
                    sa.Column('host_id',
                              sa.String(length=255), nullable=False)
                    )
