# Copyright 2016 OpenStack Foundation
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

from neutron.db import migration

"""Add desc to standard attr table

Revision ID: 0e66c5227a8a
Revises: 3894bccad37f
Create Date: 2016-02-02 10:50:34.238563

"""

# revision identifiers, used by Alembic.
revision = '0e66c5227a8a'
down_revision = '3894bccad37f'

neutron_milestone = [migration.MITAKA]


def upgrade():
    op.add_column('standardattributes', sa.Column('description',
                  sa.String(length=255), nullable=True))
