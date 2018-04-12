# Copyright 2015 HuaWei Technologies.
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

"""add_timestamp_to_base_resources

Revision ID: 3894bccad37f
Revises: 2f9e956e7532
Create Date: 2016-03-01 04:19:58.852612

"""

# revision identifiers, used by Alembic.
revision = '3894bccad37f'
down_revision = '2f9e956e7532'


def upgrade():
    for column_name in ['created_at', 'updated_at']:
        op.add_column(
            'standardattributes',
            sa.Column(column_name, sa.DateTime(), nullable=True)
        )
