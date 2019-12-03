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


"""network subnet update lock

Revision ID: a010322604bc
Revises: f4b9654dd40c
Create Date: 2019-11-20 18:05:00.812058

"""

# revision identifiers, used by Alembic.
revision = 'a010322604bc'
down_revision = 'f4b9654dd40c'


def upgrade():
    op.create_table(
        'network_subnet_lock',
        sa.Column('network_id', sa.String(length=36),
                  sa.ForeignKey('networks.id', ondelete='CASCADE'),
                  primary_key=True),
        sa.Column('subnet_id', sa.String(length=36))
    )
