# Copyright (c) 2015 Red Hat, Inc.
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

"""Initial operations in support of address scopes

"""

# revision identifiers, used by Alembic.
revision = '52c5312f6baf'
down_revision = '599c6a226151'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'address_scopes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('shared', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id'))
