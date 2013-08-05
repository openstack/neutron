# Copyright 2013 Openstack Foundation
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

"""
Upgrade/downgrade operations for 'community' extensions
"""

from alembic import op
import sqlalchemy as sa


def upgrade_l3():
    op.create_table(
        'routers',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=True),
        sa.Column('gw_port_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['gw_port_id'], ['ports.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'externalnetworks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )

    op.create_table(
        'floatingips',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('floating_ip_address', sa.String(length=64), nullable=False),
        sa.Column('floating_network_id', sa.String(length=36), nullable=False),
        sa.Column('floating_port_id', sa.String(length=36), nullable=False),
        sa.Column('fixed_port_id', sa.String(length=36), nullable=True),
        sa.Column('fixed_ip_address', sa.String(length=64), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['fixed_port_id'], ['ports.id'], ),
        sa.ForeignKeyConstraint(['floating_port_id'], ['ports.id'], ),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def upgrade_quota():
    op.create_table(
        'quotas',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(255), index=True),
        sa.Column('resource', sa.String(255)),
        sa.Column('limit', sa.Integer()),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade_l3():
    for table in ('floatingips', 'routers', 'externalnetworks'):
        op.drop_table(table)


def downgrade_quota():
    op.drop_table('quotas')
