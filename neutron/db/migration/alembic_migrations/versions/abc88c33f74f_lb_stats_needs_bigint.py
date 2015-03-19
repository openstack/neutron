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

"""lb stats

Revision ID: abc88c33f74f
Revises: 3d2585038b95
Create Date: 2014-02-24 20:14:59.577972

"""

# revision identifiers, used by Alembic.
revision = 'abc88c33f74f'
down_revision = '3d2585038b95'


from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():
    if migration.schema_has_table('poolstatisticss'):
        op.alter_column('poolstatisticss', 'bytes_in',
                        type_=sa.BigInteger(), existing_type=sa.Integer())
        op.alter_column('poolstatisticss', 'bytes_out',
                        type_=sa.BigInteger(), existing_type=sa.Integer())
        op.alter_column('poolstatisticss', 'active_connections',
                        type_=sa.BigInteger(), existing_type=sa.Integer())
        op.alter_column('poolstatisticss', 'total_connections',
                        type_=sa.BigInteger(), existing_type=sa.Integer())
