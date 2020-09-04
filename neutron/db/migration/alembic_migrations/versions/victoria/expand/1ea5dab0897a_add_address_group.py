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
from neutron_lib.db import constants as db_const
import sqlalchemy as sa


"""add address group

Revision ID: 1ea5dab0897a
Revises: fd6107509ccd
Create Date: 2020-07-02 18:43:28.380941

"""

# revision identifiers, used by Alembic.
revision = '1ea5dab0897a'
down_revision = 'fd6107509ccd'


def upgrade():
    op.create_table(
        'address_groups',
        sa.Column('project_id', sa.String(
            length=db_const.PROJECT_ID_FIELD_SIZE), index=True),
        sa.Column('id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  primary_key=True),
        sa.Column('name', sa.String(length=db_const.NAME_FIELD_SIZE),
                  nullable=True),
        sa.Column('description', sa.String(
            length=db_const.LONG_DESCRIPTION_FIELD_SIZE), nullable=True)
    )

    op.create_table(
        'address_associations',
        sa.Column('address', sa.String(length=db_const.IP_ADDR_FIELD_SIZE),
                  primary_key=True),
        sa.Column('address_group_id', sa.String(
            length=db_const.UUID_FIELD_SIZE), primary_key=True),
        sa.ForeignKeyConstraint(['address_group_id'], ['address_groups.id'],
                                ondelete='CASCADE')
    )
