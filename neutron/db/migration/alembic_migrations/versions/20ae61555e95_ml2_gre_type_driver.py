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

"""DB Migration for ML2 GRE Type Driver

Revision ID: 20ae61555e95
Revises: 13de305df56e
Create Date: 2013-07-10 17:19:03.021937

"""

# revision identifiers, used by Alembic.
revision = '20ae61555e95'
down_revision = '13de305df56e'

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

    op.create_table(
        'ml2_gre_allocations',
        sa.Column('gre_id', sa.Integer, nullable=False,
                  autoincrement=False),
        sa.Column('allocated', sa.Boolean, nullable=False),
        sa.PrimaryKeyConstraint('gre_id')
    )

    op.create_table(
        'ml2_gre_endpoints',
        sa.Column('ip_address', sa.String(length=64)),
        sa.PrimaryKeyConstraint('ip_address')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('ml2_gre_allocations')
    op.drop_table('ml2_gre_endpoints')
