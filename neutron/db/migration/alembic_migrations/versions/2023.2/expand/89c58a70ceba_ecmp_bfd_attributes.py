# Copyright 2023 OpenStack Foundation
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
from sqlalchemy import sql

from neutron.db import migration


"""Add ECMP and BFD router-level policy attributes
Revision ID: 89c58a70ceba
Revises: c33da356b165
Create Date: 2023-02-22 21:08:33.593101

"""

# revision identifiers, used by Alembic.
revision = '89c58a70ceba'
down_revision = 'c33da356b165'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.RELEASE_2023_2]


def upgrade():
    op.add_column('router_extra_attributes',
                  sa.Column('enable_default_route_ecmp', sa.Boolean(),
                            server_default=sql.false(), nullable=False))
    op.add_column('router_extra_attributes',
                  sa.Column('enable_default_route_bfd', sa.Boolean(),
                            server_default=sql.false(), nullable=False))
