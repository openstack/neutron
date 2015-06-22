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

"""neutrodb_ipam

Revision ID: 599c6a226151
Revises: 354db87e3225
Create Date: 2015-03-08 18:12:08.962378

"""

# revision identifiers, used by Alembic.
revision = '599c6a226151'
down_revision = '354db87e3225'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'ipamsubnets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('neutron_subnet_id', sa.String(length=36), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ipamallocations',
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=36), nullable=True),
        sa.Column('ipam_subnet_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['ipam_subnet_id'],
                                ['ipamsubnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('ip_address', 'ipam_subnet_id'))

    op.create_table(
        'ipamallocationpools',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('ipam_subnet_id', sa.String(length=36), nullable=False),
        sa.Column('first_ip', sa.String(length=64), nullable=False),
        sa.Column('last_ip', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['ipam_subnet_id'],
                                ['ipamsubnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ipamavailabilityranges',
        sa.Column('allocation_pool_id', sa.String(length=36), nullable=False),
        sa.Column('first_ip', sa.String(length=64), nullable=False),
        sa.Column('last_ip', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['allocation_pool_id'],
                                ['ipamallocationpools.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('allocation_pool_id', 'first_ip', 'last_ip'),
        sa.Index('ix_ipamavailabilityranges_first_ip_allocation_pool_id',
                 'first_ip', 'allocation_pool_id'),
        sa.Index('ix_ipamavailabilityranges_last_ip_allocation_pool_id',
                 'last_ip', 'allocation_pool_id'))
