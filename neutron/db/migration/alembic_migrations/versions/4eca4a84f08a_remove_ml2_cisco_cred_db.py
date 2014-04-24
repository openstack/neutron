# Copyright 2014 OpenStack Foundation
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

"""Remove ML2 Cisco Credentials DB

Revision ID: 4eca4a84f08a
Revises: 33c3db036fe4
Create Date: 2014-04-10 19:32:46.697189

"""

# revision identifiers, used by Alembic.
revision = '4eca4a84f08a'
down_revision = '33c3db036fe4'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.ml2.plugin.Ml2Plugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('cisco_ml2_credentials')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'cisco_ml2_credentials',
        sa.Column('credential_id', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('credential_name', sa.String(length=255), nullable=False),
        sa.Column('user_name', sa.String(length=255), nullable=True),
        sa.Column('password', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('tenant_id', 'credential_name')
    )
