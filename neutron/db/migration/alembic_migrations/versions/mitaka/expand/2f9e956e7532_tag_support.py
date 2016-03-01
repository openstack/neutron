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

"""tag support

Revision ID: 2f9e956e7532
Revises: 31ed664953e6
Create Date: 2016-01-21 08:11:49.604182

"""

# revision identifiers, used by Alembic.
revision = '2f9e956e7532'
down_revision = '31ed664953e6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'tags',
        sa.Column('standard_attr_id', sa.BigInteger(),
                  sa.ForeignKey('standardattributes.id', ondelete='CASCADE'),
                  nullable=False, primary_key=True),
        sa.Column('tag', sa.String(length=60), nullable=False,
                  primary_key=True)
    )
