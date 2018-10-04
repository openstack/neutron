# Copyright 2016 IBM
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

"""Add segment_host_mapping table.

Revision ID: 8fd3918ef6f4
Revises: c879c5e1ee90
Create Date: 2016-02-25 00:22:47.618593

"""

# revision identifiers, used by Alembic.
revision = '8fd3918ef6f4'
down_revision = 'c879c5e1ee90'


def upgrade():
    op.create_table('segmenthostmappings',
                    sa.Column('segment_id',
                              sa.String(length=36),
                              index=True,
                              nullable=False),
                    sa.Column('host',
                              sa.String(255),
                              index=True,
                              nullable=False),
                    sa.PrimaryKeyConstraint('segment_id', 'host'),
                    sa.ForeignKeyConstraint(['segment_id'],
                                            ['networksegments.id'],
                                            ondelete='CASCADE'))


def contract_creation_exceptions():
    """Return create exceptions.

    These elements depend on the networksegments table which was renamed
    in the contract branch.
    """
    return {
        sa.Table: ['segmenthostmappings'],
        sa.Index: ['segmenthostmappings']
    }
