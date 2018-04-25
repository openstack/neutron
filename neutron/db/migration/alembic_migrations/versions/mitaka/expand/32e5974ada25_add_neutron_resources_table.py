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

"""Add standard attribute table

Revision ID: 32e5974ada25
Revises: 13cfb89f881a
Create Date: 2015-09-10 00:22:47.618593

"""

# revision identifiers, used by Alembic.
revision = '32e5974ada25'
down_revision = '13cfb89f881a'


TABLES = ('ports', 'networks', 'subnets', 'subnetpools', 'securitygroups',
          'floatingips', 'routers', 'securitygrouprules')


def upgrade():
    op.create_table(
        'standardattributes',
        sa.Column('id', sa.BigInteger(), autoincrement=True),
        sa.Column('resource_type', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    for table in TABLES:
        op.add_column(table, sa.Column('standard_attr_id', sa.BigInteger(),
                                       nullable=True))
