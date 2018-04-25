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

"""Add resource_versions row to agent table

Revision ID: 31ed664953e6
Revises: c3a73f615e4
Create Date: 2016-01-15 13:41:30.016915

"""

# revision identifiers, used by Alembic.
revision = '31ed664953e6'
down_revision = '15e43b934f81'


def upgrade():
    op.add_column('agents',
                  sa.Column('resource_versions', sa.String(length=8191)))
