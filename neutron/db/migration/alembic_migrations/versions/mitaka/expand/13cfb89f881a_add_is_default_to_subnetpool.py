# Copyright 2015 Cisco Systems
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
from sqlalchemy import sql

"""add is_default to subnetpool

Revision ID: 13cfb89f881a
Revises: 59cb5b6cf4d
Create Date: 2015-09-30 15:58:31.170153

"""

# revision identifiers, used by Alembic.
revision = '13cfb89f881a'
down_revision = '59cb5b6cf4d'


def upgrade():
    op.add_column('subnetpools',
                  sa.Column('is_default',
                            sa.Boolean(),
                            server_default=sql.false(),
                            nullable=False))
