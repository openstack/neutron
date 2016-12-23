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

"""rbac_qos_policy

Revision ID: 15e43b934f81
Revises: 1df244e556f5
Create Date: 2015-11-25 18:45:03.819115

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '15e43b934f81'
down_revision = 'b4caf27aae4'


def upgrade():
    op.create_table('qospolicyrbacs',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('tenant_id',
                              sa.String(length=255),
                              nullable=True),
                    sa.Column('target_tenant',
                              sa.String(length=255),
                              nullable=False),
                    sa.Column('action', sa.String(length=255), nullable=False),
                    sa.Column('object_id', sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['object_id'],
                                            ['qos_policies.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('target_tenant',
                                        'object_id', 'action'))
    op.create_index(op.f('ix_qospolicyrbacs_tenant_id'), 'qospolicyrbacs',
                    ['tenant_id'], unique=False)
