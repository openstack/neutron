# Copyright 2013 OpenStack Foundation
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

"""add unique constraint to members

Revision ID: e197124d4b9
Revises: havana
Create Date: 2013-11-17 10:09:37.728903

"""

# revision identifiers, used by Alembic.
revision = 'e197124d4b9'
down_revision = 'havana'

from alembic import op

from neutron.db import migration


CONSTRAINT_NAME = 'uniq_member0pool_id0address0port'
TABLE_NAME = 'members'


def upgrade():
    if migration.schema_has_table(TABLE_NAME):
        op.create_unique_constraint(
            name=CONSTRAINT_NAME,
            source=TABLE_NAME,
            local_cols=['pool_id', 'address', 'protocol_port']
        )
