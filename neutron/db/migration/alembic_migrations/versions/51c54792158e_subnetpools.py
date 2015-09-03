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

"""Initial operations for subnetpools

Revision ID: 51c54792158e
Revises: 341ee8a4ccb5
Create Date: 2015-01-27 13:07:50.713838

"""

# revision identifiers, used by Alembic.
revision = '51c54792158e'
down_revision = '1955efc66455'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('subnetpools',
                    sa.Column('tenant_id',
                              sa.String(length=255),
                              nullable=True,
                              index=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('name', sa.String(length=255), nullable=True),
                    sa.Column('ip_version', sa.Integer(), nullable=False),
                    sa.Column('default_prefixlen',
                              sa.Integer(),
                              nullable=False),
                    sa.Column('min_prefixlen', sa.Integer(), nullable=False),
                    sa.Column('max_prefixlen', sa.Integer(), nullable=False),
                    sa.Column('shared', sa.Boolean(), nullable=False),
                    sa.Column('allow_overlap', sa.Boolean(), nullable=False),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('subnetpoolprefixes',
                    sa.Column('cidr', sa.String(length=64), nullable=False),
                    sa.Column('subnetpool_id',
                              sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['subnetpool_id'],
                                            ['subnetpools.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('cidr', 'subnetpool_id'))
