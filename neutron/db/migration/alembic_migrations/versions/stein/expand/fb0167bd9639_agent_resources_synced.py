# Copyright 2019 OpenStack Foundation
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


"""agent_resources_synced

Revision ID: fb0167bd9639
Revises: 195176fb410d
Create Date: 2019-01-04 12:34:44.563725

"""

# revision identifiers, used by Alembic.
revision = 'fb0167bd9639'
down_revision = '195176fb410d'


def upgrade():
    op.add_column(
        'agents',
        sa.Column('resources_synced', sa.Boolean(), server_default=None))
