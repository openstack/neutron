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

"""Cisco Nexus multi-switch

Revision ID: 3a520dd165d0
Revises: 2528ceb28230
Create Date: 2013-09-28 15:23:38.872682

"""

# revision identifiers, used by Alembic.
revision = '3a520dd165d0'
down_revision = '2528ceb28230'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.cisco.network_plugin.PluginV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.add_column(
        'cisco_nexusport_bindings',
        sa.Column('instance_id', sa.String(length=255), nullable=False))
    op.add_column(
        'cisco_nexusport_bindings',
        sa.Column('switch_ip', sa.String(length=255), nullable=False))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_column('cisco_nexusport_bindings', 'switch_ip')
    op.drop_column('cisco_nexusport_bindings', 'instance_id')
