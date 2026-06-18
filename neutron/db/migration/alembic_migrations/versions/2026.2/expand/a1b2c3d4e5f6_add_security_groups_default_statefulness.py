# Copyright 2026 OpenStack Foundation
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

"""Add security groups default statefulness table

Revision ID: a1b2c3d4e5f6
Revises: a00aa97899c0
Create Date: 2026-05-12 10:00:00.000000

"""

from neutron_lib.db import constants as db_const
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = 'a00aa97899c0'


def upgrade():
    migration.create_table_if_not_exists(
        'security_groups_default_statefulness',
        sa.Column('id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  primary_key=True),
        sa.Column('project_id',
                  sa.String(length=db_const.PROJECT_ID_FIELD_SIZE),
                  nullable=True, unique=True),
        sa.Column('stateful', sa.Boolean(), nullable=False,
                  server_default=sa.sql.true()),
    )
