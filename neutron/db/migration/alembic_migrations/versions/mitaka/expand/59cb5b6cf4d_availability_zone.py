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

"""Add availability zone

Revision ID: 59cb5b6cf4d
Revises: 34af2b5c5a59
Create Date: 2015-01-20 14:38:47.156574

"""

# revision identifiers, used by Alembic.
revision = '59cb5b6cf4d'
down_revision = '34af2b5c5a59'


def upgrade():
    op.add_column('agents',
                  sa.Column('availability_zone', sa.String(length=255)))
