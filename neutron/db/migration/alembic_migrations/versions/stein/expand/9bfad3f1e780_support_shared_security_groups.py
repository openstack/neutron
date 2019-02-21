# Copyright 2019 OpenStack Foundation
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


"""support shared security groups

Revision ID: 9bfad3f1e780
Revises: 0ff9e3881597
Create Date: 2019-02-05 15:24:45.011378

"""

# revision identifiers, used by Alembic.
revision = '9bfad3f1e780'
down_revision = '0ff9e3881597'


def upgrade():
    op.create_table(
        'securitygrouprbacs',
        sa.Column('project_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_tenant', sa.String(length=255), nullable=False),
        sa.Column('action', sa.String(length=255), nullable=False),
        sa.Column('object_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['object_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('target_tenant', 'object_id', 'action',
                            name='uniq_securitygrouprbacs0'
                                 'target_tenant0object_id0action')
    )
    op.create_index(op.f('ix_securitygrouprbacs_project_id'),
                    'securitygrouprbacs', ['project_id'], unique=False)
