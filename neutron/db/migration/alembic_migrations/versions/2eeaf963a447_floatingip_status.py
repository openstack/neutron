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

"""floatingip_status

Revision ID: 2eeaf963a447
Revises: e766b19a3bb
Create Date: 2014-01-14 11:58:13.754747

"""

# revision identifiers, used by Alembic.
revision = '2eeaf963a447'
down_revision = 'e766b19a3bb'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():

    if not migration.schema_has_table('floatingips'):
        # In the database we are migrating from, the configured plugin
        # did not create the floatingips table.
        return

    op.add_column('floatingips',
                  sa.Column('last_known_router_id',
                            sa.String(length=36),
                            nullable=True))
    op.add_column('floatingips',
                  sa.Column('status',
                            sa.String(length=16),
                            nullable=True))
