# Copyright 2015 OpenStack Foundation
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

"""sync with cisco repo

Revision ID: 341ee8a4ccb5
Revises: f15b1fb526dd
Create Date: 2015-03-10 17:19:57.047080

"""

# revision identifiers, used by Alembic.
revision = '341ee8a4ccb5'
down_revision = 'f15b1fb526dd'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'ml2_nexus_vxlan_allocations',
        sa.Column('vxlan_vni', sa.Integer(), nullable=False,
                  autoincrement=False),
        sa.Column('allocated', sa.Boolean(), nullable=False,
                  server_default=sa.sql.false()),
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

    op.create_table(
        'cisco_ml2_nexus_nve',
        sa.Column('vni', sa.Integer(), nullable=False),
        sa.Column('switch_ip', sa.String(length=255), nullable=True),
        sa.Column('device_id', sa.String(length=255), nullable=True),
        sa.Column('mcast_group', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('vni', 'switch_ip', 'device_id'))

    op.add_column(
        'cisco_ml2_nexusport_bindings',
        sa.Column('vni', sa.Integer(), nullable=True))

    op.add_column('cisco_ml2_nexusport_bindings', sa.Column(
        'is_provider_vlan', sa.Boolean(), nullable=False,
        server_default=sa.sql.false()))
