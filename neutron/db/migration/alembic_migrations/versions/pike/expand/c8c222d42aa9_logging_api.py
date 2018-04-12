# Copyright 2017 OpenStack Foundation
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

from neutron_lib.db import constants as db_const

"""logging api

Revision ID: c8c222d42aa9
Revises: 62c781cb6192
Create Date: 2017-05-30 11:51:08.173604

"""

# revision identifiers, used by Alembic.
revision = 'c8c222d42aa9'
down_revision = '62c781cb6192'


def upgrade():

    op.create_table(
        'logs',
        sa.Column('project_id',
                  sa.String(length=db_const.PROJECT_ID_FIELD_SIZE),
                  nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('standard_attr_id', sa.BigInteger(), nullable=False),
        sa.Column('name', sa.String(length=db_const.NAME_FIELD_SIZE),
                  nullable=True),
        sa.Column('resource_type', sa.String(length=36), nullable=False),
        sa.Column('resource_id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  nullable=True,
                  index=True),
        sa.Column('target_id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  nullable=True,
                  index=True),
        sa.Column('event', sa.String(length=255), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['standard_attr_id'],
                                ['standardattributes.id'],
                                ondelete='CASCADE'),
        sa.UniqueConstraint('standard_attr_id'))
