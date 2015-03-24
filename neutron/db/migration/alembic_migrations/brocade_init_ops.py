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

# Initial operations for the Mellanox plugin

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'brocadenetworks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vlan', sa.String(length=10), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'brocadeports',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('physical_interface', sa.String(length=36), nullable=True),
        sa.Column('vlan_id', sa.String(length=36), nullable=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['brocadenetworks.id'], ),
        sa.PrimaryKeyConstraint('port_id'))
