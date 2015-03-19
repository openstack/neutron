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

"""extra_dhcp_options IPv6 support

Revision ID: 16cdf118d31d
Revises: 14be42f3d0a5
Create Date: 2014-10-23 17:04:19.796731

"""

# revision identifiers, used by Alembic.
revision = '16cdf118d31d'
down_revision = '14be42f3d0a5'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

CONSTRAINT_NAME_OLD = 'uidx_portid_optname'
CONSTRAINT_NAME_NEW = 'uniq_extradhcpopts0portid0optname0ipversion'
TABLE_NAME = 'extradhcpopts'


def upgrade():
    with migration.remove_fks_from_table(TABLE_NAME):
        op.drop_constraint(
            name=CONSTRAINT_NAME_OLD,
            table_name=TABLE_NAME,
            type_='unique'
        )

        op.add_column('extradhcpopts', sa.Column('ip_version', sa.Integer(),
                  server_default='4', nullable=False))
        op.execute("UPDATE extradhcpopts SET ip_version = 4")

    op.create_unique_constraint(
        name=CONSTRAINT_NAME_NEW,
        source='extradhcpopts',
        local_cols=['port_id', 'opt_name', 'ip_version']
    )
