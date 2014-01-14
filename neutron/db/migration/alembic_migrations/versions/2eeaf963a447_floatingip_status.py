# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

"""floatingip_status

Revision ID: 2eeaf963a447
Revises: f44ab9871cd6
Create Date: 2014-01-14 11:58:13.754747

"""

# revision identifiers, used by Alembic.
revision = '2eeaf963a447'
down_revision = 'f44ab9871cd6'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    '*'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.add_column('floatingips',
                  sa.Column('last_known_router_id',
                            sa.String(length=36),
                            nullable=True))
    op.add_column('floatingips',
                  sa.Column('status',
                            sa.String(length=16),
                            nullable=True))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.drop_column('floatingips', 'last_known_router_id')
    op.drop_column('floatingips', 'status')
