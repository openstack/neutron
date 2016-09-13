# Copyright 2016 Mirantis
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

"""Add flavor_id to Router

Revision ID: 3d0e74aa7d37
Revises: a963b38d82f4
Create Date: 2016-05-05 00:22:47.618593

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3d0e74aa7d37'
down_revision = 'a963b38d82f4'


def upgrade():
    op.add_column('routers',
                  sa.Column('flavor_id',
                            sa.String(length=36),
                            sa.ForeignKey('flavors.id'),
                            nullable=True))
