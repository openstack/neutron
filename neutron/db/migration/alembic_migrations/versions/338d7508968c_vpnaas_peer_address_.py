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

"""vpnaas peer_address size increase

Revision ID: 338d7508968c
Revises: 4a666eb208c2
Create Date: 2013-09-16 11:31:39.410189

"""

# revision identifiers, used by Alembic.
revision = '338d7508968c'
down_revision = '4a666eb208c2'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.services.vpn.plugin.VPNDriverPlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.alter_column('ipsec_site_connections', 'peer_address',
                    type_=sa.String(255), existing_type=sa.String(64))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.alter_column('ipsec_site_connections', 'peer_address',
                    type_=sa.String(64), existing_type=sa.String(255))
