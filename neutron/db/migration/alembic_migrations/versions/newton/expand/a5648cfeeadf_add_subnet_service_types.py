# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
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

"""Add support for Subnet Service Types

Revision ID: a5648cfeeadf
Revises: 030a959ceafa
Create Date: 2016-03-15 18:00:00.190173

"""

# revision identifiers, used by Alembic.
revision = 'a5648cfeeadf'
down_revision = '030a959ceafa'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('subnet_service_types',
        sa.Column('subnet_id', sa.String(length=36)),
        sa.Column('service_type', sa.String(length=255)),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subnet_id', 'service_type')
    )
