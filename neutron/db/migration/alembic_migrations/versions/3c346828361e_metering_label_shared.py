# Copyright 2014 OpenStack Foundation
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

"""metering_label_shared

Revision ID: 3c346828361e
Revises: 16a27a58e093
Create Date: 2014-08-27 15:03:46.537290

"""

# revision identifiers, used by Alembic.
revision = '3c346828361e'
down_revision = '16a27a58e093'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('meteringlabels', sa.Column('shared', sa.Boolean(),
                                              server_default=sa.sql.false(),
                                              nullable=True))
