# Copyright 2020 OpenStack Foundation
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
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import sql


"""add rbac support for subnetpool

Revision ID: e88badaa9591
Revises: e4e236b0e1ff
Create Date: 2020-02-10 12:30:30.060646

"""

# revision identifiers, used by Alembic.
revision = 'e88badaa9591'
down_revision = 'e4e236b0e1ff'
depends_on = ('7d9d8eeec6ad',)


def upgrade():
    subnetpool_rbacs = op.create_table(
        'subnetpoolrbacs', sa.MetaData(),
        sa.Column('project_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_tenant', sa.String(length=255), nullable=False),
        sa.Column('action', sa.String(length=255), nullable=False),
        sa.Column('object_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['object_id'], ['subnetpools.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('target_tenant', 'object_id', 'action',
                            name='uniq_subnetpools_rbacs0'
                            'target_tenant0object_id0action')
    )

    op.alter_column('subnetpools', 'shared', server_default=sql.false())

    op.bulk_insert(
        subnetpool_rbacs,
        get_rbac_policies_for_shared_subnetpools()
    )

    op.create_index(op.f('ix_subnetpoolrbacs_project_id'),
                    'subnetpoolrbacs', ['project_id'], unique=False)


def get_rbac_policies_for_shared_subnetpools():
    # A simple model of the subnetpools table with only the fields needed for
    # the migration.
    subnetpool = sa.Table(
        'subnetpools', sa.MetaData(),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=255)),
        sa.Column('shared', sa.Boolean(), nullable=False)
    )

    session = sa.orm.Session(bind=op.get_bind())
    values = []
    for row in session.query(subnetpool).filter(subnetpool.c.shared).all():
        values.append({'id': uuidutils.generate_uuid(), 'object_id': row[0],
                       'project_id': row[1], 'target_tenant': '*',
                       'action': 'access_as_shared'})
    # this commit appears to be necessary to allow further operations
    session.commit()
    return values
