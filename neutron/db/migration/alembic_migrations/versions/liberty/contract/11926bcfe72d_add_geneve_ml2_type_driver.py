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

from alembic import op
import sqlalchemy as sa

"""add geneve ml2 type driver

Revision ID: 11926bcfe72d
Revises: 2e5352a0ad4d
Create Date: 2015-08-27 19:56:16.356522

"""

# revision identifiers, used by Alembic.
revision = '11926bcfe72d'
down_revision = '2e5352a0ad4d'


def contract_creation_exceptions():
    """These elements were created by mistake in the contract branch."""
    return {
        sa.Table: ['ml2_geneve_allocations', 'ml2_geneve_endpoints'],
        sa.Index: ['ml2_geneve_allocations']
    }


def upgrade():
    op.create_table(
        'ml2_geneve_allocations',
        sa.Column('geneve_vni', sa.Integer(),
                  autoincrement=False, nullable=False),
        sa.Column('allocated', sa.Boolean(),
                  server_default=sa.sql.false(), nullable=False),
        sa.PrimaryKeyConstraint('geneve_vni'),
    )
    op.create_index(op.f('ix_ml2_geneve_allocations_allocated'),
                    'ml2_geneve_allocations', ['allocated'], unique=False)
    op.create_table(
        'ml2_geneve_endpoints',
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('ip_address'),
        sa.UniqueConstraint('host', name='unique_ml2_geneve_endpoints0host'),
    )
