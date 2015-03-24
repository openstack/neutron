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

"""cisco_csr_routing

Revision ID: 58fe87a01143
Revises: 32f3915891fd
Create Date: 2014-08-18 17:14:12.506356

"""

# revision identifiers, used by Alembic.
revision = '58fe87a01143'
down_revision = '32f3915891fd'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('cisco_hosting_devices',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('complementary_id', sa.String(length=36), nullable=True),
        sa.Column('device_id', sa.String(length=255), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('management_port_id', sa.String(length=36), nullable=True),
        sa.Column('protocol_port', sa.Integer(), nullable=True),
        sa.Column('cfg_agent_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.ForeignKeyConstraint(['cfg_agent_id'], ['agents.id'], ),
        sa.ForeignKeyConstraint(['management_port_id'], ['ports.id'],
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table('cisco_port_mappings',
        sa.Column('logical_resource_id', sa.String(length=36), nullable=False),
        sa.Column('logical_port_id', sa.String(length=36), nullable=False),
        sa.Column('port_type', sa.String(length=32), nullable=True),
        sa.Column('network_type', sa.String(length=32), nullable=True),
        sa.Column('hosting_port_id', sa.String(length=36), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), autoincrement=False,
                  nullable=True),
        sa.ForeignKeyConstraint(['hosting_port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['logical_port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('logical_resource_id', 'logical_port_id')
    )
    op.create_table('cisco_router_mappings',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('auto_schedule', sa.Boolean(), nullable=False),
        sa.Column('hosting_device_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['hosting_device_id'],
                                ['cisco_hosting_devices.id'],
                                ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id')
    )
