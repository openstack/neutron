# Copyright 2021 OpenStack Foundation
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

"""increase tag elements from 60 to 255 chars

Revision ID: 8df53b0d2c0e
Revises: 6135a7bd4425
Create Date: 2021-03-29 14:44:35.607053

"""

# revision identifiers, used by Alembic.
revision = '8df53b0d2c0e'
down_revision = '6135a7bd4425'

TABLE = 'tags'


def upgrade():
    op.alter_column(TABLE, 'tag', existing_type=sa.String(60),
                    type_=sa.String(255), existing_nullable=False)
