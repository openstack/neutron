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

"""add_rbac_support_for_address_group

Revision ID: 6135a7bd4425
Revises: 1e0744e4ffea
Create Date: 2021-01-22 11:24:07.435031

"""

# revision identifiers, used by Alembic.
revision = '6135a7bd4425'
down_revision = '1e0744e4ffea'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.WALLABY]


def upgrade():
    op.create_table(
        'addressgrouprbacs', sa.MetaData(),
        sa.Column('project_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False,
                  primary_key=True),
        sa.Column('target_tenant', sa.String(length=255), nullable=False),
        sa.Column('action', sa.String(length=255), nullable=False),
        sa.Column('object_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['object_id'], ['address_groups.id'],
                                ondelete='CASCADE'),
        sa.UniqueConstraint('target_tenant', 'object_id', 'action',
                            name='uniq_address_groups_rbacs0'
                                 'target_tenant0object_id0action')
    )
