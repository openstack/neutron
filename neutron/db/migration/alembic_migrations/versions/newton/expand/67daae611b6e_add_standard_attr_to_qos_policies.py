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

"""add standardattr to qos policies

Revision ID: 67daae611b6e
Revises: a5648cfeeadf
Create Date: 2016-08-18 14:10:30.021015

"""

revision = '67daae611b6e'
down_revision = '0f5bef0f87d4'


TABLE = 'qos_policies'


def upgrade():
    op.add_column(TABLE, sa.Column('standard_attr_id', sa.BigInteger(),
                                   nullable=True))
