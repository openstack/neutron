# Copyright 2024 OpenStack Foundation
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


# Add qinq column to the Network table
#
# Revision ID: ad80a9f07c5c
# Revises: 5bcb7b31ec7d
# Create Date: 2024-12-09 11:27:41.108660

# revision identifiers, used by Alembic.
revision = 'ad80a9f07c5c'
down_revision = '5bcb7b31ec7d'


def upgrade():
    op.add_column(
        'networks',
        sa.Column('qinq', sa.Boolean(), server_default=None)
    )
