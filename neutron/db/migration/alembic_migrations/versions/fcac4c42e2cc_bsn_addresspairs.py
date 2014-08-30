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

"""bsn_addresspairs

Revision ID: fcac4c42e2cc
Revises: 2eeaf963a447
Create Date: 2014-02-23 12:56:00.402855

"""

# revision identifiers, used by Alembic.
revision = 'fcac4c42e2cc'
down_revision = '2eeaf963a447'

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

    op.create_table(
        'allowedaddresspairs',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('mac_address', sa.String(length=32), nullable=False),
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id', 'mac_address', 'ip_address'),
    )


def downgrade(active_plugins=None, options=None):
    pass