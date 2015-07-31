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

"""network_rbac

Revision ID: 8675309a5c4f
Revises: 313373c0ffee
Create Date: 2015-06-14 13:12:04.012457

"""

# revision identifiers, used by Alembic.
revision = '8675309a5c4f'
down_revision = '313373c0ffee'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'networkrbacs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('object_id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('target_tenant', sa.String(length=255), nullable=False),
        sa.Column('action', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['object_id'],
                                ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'action', 'object_id', 'target_tenant',
            name='uniq_networkrbacs0tenant_target0object_id0action'))
