# Copyright 2022 OpenStack Foundation
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

"""drop portbindingports table

Revision ID: 8160f7a9cebb
Revises: 1ffef8d6f371
Create Date: 2022-01-08 01:55:56.519076

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8160f7a9cebb'
down_revision = '1ffef8d6f371'


def upgrade():
    op.drop_table('portbindingports')


def expand_drop_exceptions():
    """Support dropping 'portbindingports' table"""

    return {
        sa.Table: ['portbindingports']
    }
