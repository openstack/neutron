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

"""Pool Monitor status field

Revision ID: 11c6e18605c8
Revises: 52ff27f7567a
Create Date: 2013-07-10 06:07:20.878520

"""

# revision identifiers, used by Alembic.
revision = '11c6e18605c8'
down_revision = '52ff27f7567a'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.services.loadbalancer.plugin.LoadBalancerPlugin',
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.add_column('poolmonitorassociations', sa.Column('status',
                                                       sa.String(16),
                                                       nullable=False))
    op.add_column('poolmonitorassociations', sa.Column('status_description',
                                                       sa.String(255)))

    # Set status to ACTIVE for existing associations
    op.execute("UPDATE poolmonitorassociations SET status='ACTIVE'")


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_column('poolmonitorassociations', 'status')
    op.drop_column('poolmonitorassociations', 'status_description')
