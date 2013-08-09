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

"""ryu plugin update

Revision ID: 49332180ca96
Revises: 1149d7de0cfa
Create Date: 2013-01-30 07:52:58.472885

"""

# revision identifiers, used by Alembic.
revision = '49332180ca96'
down_revision = '1149d7de0cfa'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.ryu.ryu_neutron_plugin.RyuNeutronPluginV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('ofp_server')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'ofp_server',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('address', sa.String(length=255)),
        sa.Column('host_type', sa.String(length=255)),
        sa.PrimaryKeyConstraint(u'id')
    )
