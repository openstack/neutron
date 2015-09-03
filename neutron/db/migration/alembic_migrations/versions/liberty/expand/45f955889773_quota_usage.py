# Copyright 2015 OpenStack Foundation
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

"""quota_usage

Revision ID: 45f955889773
Revises: 8675309a5c4f
Create Date: 2015-04-17 08:09:37.611546

"""

# revision identifiers, used by Alembic.
revision = '45f955889773'
down_revision = '8675309a5c4f'

from alembic import op
import sqlalchemy as sa
from sqlalchemy import sql


def upgrade():
    op.create_table(
        'quotausages',
        sa.Column('tenant_id', sa.String(length=255),
                  nullable=False, primary_key=True, index=True),
        sa.Column('resource', sa.String(length=255),
                  nullable=False, primary_key=True, index=True),
        sa.Column('dirty', sa.Boolean(), nullable=False,
                  server_default=sql.false()),
        sa.Column('in_use', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('reserved', sa.Integer(), nullable=False,
                  server_default='0'))
