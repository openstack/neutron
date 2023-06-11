# Copyright 2019 x-ion GmbH
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
from neutron_lib.db import constants as db_const
import sqlalchemy as sa

"""Add table and relations for subnet dns_publish_fixed_ip attribute

Revision ID: 263d454a9655
Revises: a010322604bc
Create Date: 2019-05-24 10:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = '263d454a9655'
down_revision = 'a010322604bc'


def upgrade():
    op.create_table('subnet_dns_publish_fixed_ips',
                    sa.Column('subnet_id',
                              sa.String(length=db_const.UUID_FIELD_SIZE),
                              nullable=False),
                    sa.Column('dns_publish_fixed_ip',
                              sa.Boolean(),
                              nullable=False,
                              server_default=sa.sql.false()),
                    sa.ForeignKeyConstraint(['subnet_id'],
                                            ['subnets.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('subnet_id'))
