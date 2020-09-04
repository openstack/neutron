# Copyright 2014-2015 OpenStack Foundation
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

from alembic import op
import sqlalchemy as sa

"""Flavor framework

Revision ID: 313373c0ffee
Revises: 52c5312f6baf

Create Date: 2014-07-17 03:00:00.00
"""
# revision identifiers, used by Alembic.
revision = '313373c0ffee'
down_revision = '52c5312f6baf'


def upgrade():
    op.create_table(
        'flavors',
        sa.Column('id', sa.String(36)),
        sa.Column('name', sa.String(255)),
        sa.Column('description', sa.String(1024)),
        sa.Column('enabled', sa.Boolean, nullable=False,
                  server_default=sa.sql.true()),
        sa.Column('service_type', sa.String(36), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'serviceprofiles',
        sa.Column('id', sa.String(36)),
        sa.Column('description', sa.String(1024)),
        sa.Column('driver', sa.String(1024), nullable=False),
        sa.Column('enabled', sa.Boolean, nullable=False,
                  server_default=sa.sql.true()),
        sa.Column('metainfo', sa.String(4096)),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'flavorserviceprofilebindings',
        sa.Column('service_profile_id', sa.String(36), nullable=False),
        sa.Column('flavor_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['service_profile_id'],
                                ['serviceprofiles.id']),
        sa.ForeignKeyConstraint(['flavor_id'], ['flavors.id']),
        sa.PrimaryKeyConstraint('service_profile_id', 'flavor_id')
    )
