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

"""add revisions table

Revision ID: c415aab1c048
Revises: 30107ab6a3ee
Create Date: 2016-04-11 03:16:24.742290
"""

# revision identifiers, used by Alembic.
revision = 'c415aab1c048'
down_revision = '30107ab6a3ee'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'standardattributes',
        sa.Column('revision_number', sa.BigInteger(),
                  nullable=False, server_default='0'))
