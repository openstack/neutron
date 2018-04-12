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

from neutron.db import migration

"""add mtu for networks

Revision ID: 7d32f979895f
Revises: c8c222d42aa9
Create Date: 2017-07-13 19:25:29.204547

"""

# revision identifiers, used by Alembic.
revision = '7d32f979895f'
down_revision = '349b6fd605a6'

# require the migration rule that dropped the mtu column in the past
depends_on = ('b67e765a3524',)

neutron_milestone = [migration.PIKE]


def upgrade():
    op.add_column('networks',
                  sa.Column('mtu',
                            sa.Integer(),
                            nullable=True))
