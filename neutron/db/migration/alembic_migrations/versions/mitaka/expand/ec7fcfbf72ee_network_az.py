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

"""Add network availability zone

Revision ID: ec7fcfbf72ee
Revises: 32e5974ada25
Create Date: 2015-09-17 09:21:51.257579

"""

# revision identifiers, used by Alembic.
revision = 'ec7fcfbf72ee'
down_revision = '32e5974ada25'


def upgrade():
    op.add_column('networks',
                  sa.Column('availability_zone_hints', sa.String(length=255)))
