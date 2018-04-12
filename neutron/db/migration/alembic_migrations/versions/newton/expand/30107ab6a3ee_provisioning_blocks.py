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

from alembic import op
import sqlalchemy as sa

"""provisioning_blocks.py

Revision ID: 30107ab6a3ee
Revises: d3435b514502
Create Date: 2016-04-15 05:59:59.000001

"""

# revision identifiers, used by Alembic.
revision = '30107ab6a3ee'
down_revision = 'd3435b514502'


def upgrade():
    op.create_table(
        'provisioningblocks',
        sa.Column('standard_attr_id', sa.BigInteger(),
                  sa.ForeignKey('standardattributes.id', ondelete='CASCADE'),
                  nullable=False, primary_key=True),
        sa.Column('entity', sa.String(length=255), nullable=False,
                  primary_key=True),
    )
