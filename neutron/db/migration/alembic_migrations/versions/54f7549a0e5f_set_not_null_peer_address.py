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

"""set_not_null_peer_address

Revision ID: 54f7549a0e5f
Revises: 33dd0a9fa487
Create Date: 2014-03-17 11:00:17.539028

"""

# revision identifiers, used by Alembic.
revision = '54f7549a0e5f'
down_revision = 'icehouse'

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
                    existing_type=sa.String(255), nullable=False)


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.alter_column('ipsec_site_connections', 'peer_address', nullable=True,
                    existing_type=sa.String(255))
