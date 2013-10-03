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

"""DB Migration for ML2 VXLAN Type Driver

Revision ID: 477a4488d3f4
Revises: 20ae61555e95
Create Date: 2013-07-09 14:14:33.158502

"""

# revision identifiers, used by Alembic.
revision = '477a4488d3f4'
down_revision = '20ae61555e95'

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
        'ml2_vxlan_allocations',
        sa.Column('vxlan_vni', sa.Integer, nullable=False,
                  autoincrement=False),
        sa.Column('allocated', sa.Boolean, nullable=False),
        sa.PrimaryKeyConstraint('vxlan_vni')
    )

    op.create_table(
        'ml2_vxlan_endpoints',
        sa.Column('ip_address', sa.String(length=64)),
        sa.Column('udp_port', sa.Integer(), nullable=False,
                  autoincrement=False),
        sa.PrimaryKeyConstraint('ip_address', 'udp_port')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('ml2_vxlan_allocations')
    op.drop_table('ml2_vxlan_endpoints')
