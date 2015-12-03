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

"""Add router availability zone

Revision ID: dce3ec7a25c9
Revises: ec7fcfbf72ee
Create Date: 2015-09-17 09:36:17.468901

"""

# revision identifiers, used by Alembic.
revision = 'dce3ec7a25c9'
down_revision = 'ec7fcfbf72ee'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('router_extra_attributes',
                  sa.Column('availability_zone_hints', sa.String(length=255)))
