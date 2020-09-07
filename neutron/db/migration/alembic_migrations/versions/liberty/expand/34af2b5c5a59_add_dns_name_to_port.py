# Copyright 2015 Rackspace
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
from neutron_lib.db import constants
import sqlalchemy as sa

from neutron.db import migration

"""Add dns_name to Port

Revision ID: 34af2b5c5a59
Revises: 9859ac9c136
Create Date: 2015-08-23 00:22:47.618593

"""

# revision identifiers, used by Alembic.
revision = '34af2b5c5a59'
down_revision = '9859ac9c136'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.LIBERTY]


def upgrade():
    op.add_column('ports',
                  sa.Column('dns_name',
                            sa.String(length=constants.FQDN_FIELD_SIZE),
                            nullable=True))
