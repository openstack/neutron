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

"""NEC OpenFlow Router

Revision ID: 66a59a7f516
Revises: 32a65f71af51
Create Date: 2013-09-03 22:16:31.446031

"""

# revision identifiers, used by Alembic.
revision = '66a59a7f516'
down_revision = '32a65f71af51'

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

    op.create_table(
        'ofcroutermappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id'),
    )
    op.create_table(
        'routerproviders',
        sa.Column('provider', sa.String(length=255), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'),
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('routerproviders')
    op.drop_table('ofcroutermappings')
