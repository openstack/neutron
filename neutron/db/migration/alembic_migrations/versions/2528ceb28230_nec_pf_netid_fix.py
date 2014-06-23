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

"""NEC PacketFilter network_id nullable fix

Revision ID: 2528ceb28230
Revises: 1064e98b7917
Create Date: 2013-09-24 12:07:43.124256

"""

# revision identifiers, used by Alembic.
revision = '2528ceb28230'
down_revision = '1064e98b7917'

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

    op.alter_column('packetfilters', 'network_id',
                    existing_type=sa.String(length=36),
                    nullable=False)


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    # NOTE(amotoki): There is a bug that nullable of network_id is
    # set to True by mistake in folsom_initial (bug 1229508).
    # To make sure nullable=False in any revision, nullable is set
    # to False in both upgrade and downgrade.
    op.alter_column('packetfilters', 'network_id',
                    existing_type=sa.String(length=36),
                    nullable=False)
