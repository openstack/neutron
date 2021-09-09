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


"""ovn backend

Revision ID: f4b9654dd40c
Revises: 86274d77933e
Create Date: 2019-11-25 13:09:31.367837

"""

# revision identifiers, used by Alembic.
revision = 'f4b9654dd40c'
down_revision = '86274d77933e'

OVN_REVISION_NUMBERS = 'ovn_revision_numbers'
OVN_HASH_RING = 'ovn_hash_ring'


def upgrade():
    inspector = sa.inspect(op.get_bind())
    table_names = inspector.get_table_names()
    if OVN_REVISION_NUMBERS in table_names and OVN_HASH_RING in table_names:
        op.alter_column(OVN_REVISION_NUMBERS, 'revision_number',
                        nullable=False, server_default='0',
                        existing_type=sa.BIGINT(), existing_nullable=False)
        return

    op.create_table(
        OVN_REVISION_NUMBERS,
        sa.Column('standard_attr_id', sa.BigInteger, nullable=True),
        sa.Column('resource_uuid', sa.String(36), nullable=False, index=True),
        sa.Column('resource_type', sa.String(36), nullable=False, index=True),
        sa.Column('revision_number', sa.BigInteger, nullable=False,
                  server_default='0'),
        sa.Column('created_at', sa.DateTime, nullable=False,
                  default=sa.func.now()),
        sa.Column('updated_at', sa.TIMESTAMP, default=sa.func.now(),
                  onupdate=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(
            ['standard_attr_id'], ['standardattributes.id'],
            ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('resource_uuid', 'resource_type')
    )

    op.create_table(
        OVN_HASH_RING,
        sa.Column('node_uuid', sa.String(36), nullable=False, index=True),
        sa.Column('group_name', sa.String(length=256), nullable=False,
                  index=True),
        sa.Column('hostname', sa.String(length=256), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False,
                  default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False,
                  default=sa.func.now()),
        sa.PrimaryKeyConstraint('node_uuid', 'group_name'),
    )
