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

"""add unique constraint to members

Revision ID: e197124d4b9
Revises: havana
Create Date: 2013-11-17 10:09:37.728903

"""

# revision identifiers, used by Alembic.
revision = 'e197124d4b9'
down_revision = 'havana'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.services.loadbalancer.plugin.LoadBalancerPlugin',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
]

from alembic import op

from neutron.db import migration


CONSTRAINT_NAME = 'uniq_member0pool_id0address0port'
TABLE_NAME = 'members'


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_unique_constraint(
        name=CONSTRAINT_NAME,
        source=TABLE_NAME,
        local_cols=['pool_id', 'address', 'protocol_port']
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_constraint(
        CONSTRAINT_NAME,
        TABLE_NAME,
        type_='unique'
    )
