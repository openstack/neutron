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

"""ML2 Nexus VxLan Type Driver

Revision ID: 208b451f0e97
Revises: 33a3d31845ad
Create Date: 2014-08-22 08:05:01.441845

"""

# revision identifiers, used by Alembic.
revision = '208b451f0e97'
down_revision = '33a3d31845ad'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'ml2_nexus_vxlan_allocations',
        sa.Column('vxlan_vni', sa.Integer(), autoincrement=False),
        sa.Column('allocated', sa.Boolean(), autoincrement=False,
                  nullable=False),
        sa.PrimaryKeyConstraint('vxlan_vni')
    )

    op.create_table(
        'ml2_nexus_vxlan_mcast_groups',
        sa.Column('id', sa.String(length=36), nullable=False), 
        sa.Column('mcast_group', sa.String(length=64), nullable=False),
        sa.Column('associated_vni', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['associated_vni'],
                                ['ml2_nexus_vxlan_allocations.vxlan_vni'],
                                ondelete='CASCADE')
    )

def downgrade(active_plugins=None, options=None):
    op.drop_table('ml2_nexus_vxlan_mcast_groups')
    op.drop_table('ml2_nexus_vxlan_allocations')
