# Copyright 2014 OpenStack Foundation
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

"""bsn_consistencyhashes

Revision ID: 81c553f3776c
Revises: 24c7ea5160d7
Create Date: 2014-02-26 18:56:00.402855

"""

# revision identifiers, used by Alembic.
revision = '81c553f3776c'
down_revision = '24c7ea5160d7'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'consistencyhashes',
        sa.Column('hash_id', sa.String(255), primary_key=True),
        sa.Column('hash', sa.String(255), nullable=False)
    )
