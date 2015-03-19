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

"""Brocade ML2 Mech. Driver

Revision ID: 492a106273f8
Revises: 2eeaf963a447
Create Date: 2014-03-03 15:35:46.974523

"""

# revision identifiers, used by Alembic.
revision = '492a106273f8'
down_revision = '2eeaf963a447'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'ml2_brocadenetworks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vlan', sa.String(length=10), nullable=True),
        sa.Column('segment_id', sa.String(length=36), nullable=True),
        sa.Column('network_type', sa.String(length=10), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ml2_brocadeports',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('admin_state_up', sa.Boolean()),
        sa.Column('physical_interface', sa.String(length=36), nullable=True),
        sa.Column('vlan_id', sa.String(length=36), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['network_id'], ['ml2_brocadenetworks.id']))
