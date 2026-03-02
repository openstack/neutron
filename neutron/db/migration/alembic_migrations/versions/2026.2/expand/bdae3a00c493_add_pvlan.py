# Copyright 2026 OpenStack Foundation
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

from neutron_lib.services.pvlan import constants as pvlan_const
import sqlalchemy as sa

from neutron.db import migration


# add_pvlan
#
# Revision ID: bdae3a00c493
# Revises: b1bca967e19d
# Create Date: 2026-02-13 17:24:51.983296

# revision identifiers, used by Alembic.
revision = 'bdae3a00c493'
down_revision = 'b1bca967e19d'


def upgrade():
    migration.create_table_if_not_exists(
        'networkpvlan',
        sa.Column('network_id', sa.String(length=36),
                  sa.ForeignKey('networks.id', ondelete='CASCADE'),
                  primary_key=True),
        sa.Column('pvlan', sa.Boolean(), nullable=False,
                  server_default=sa.sql.false()))

    migration.create_table_if_not_exists(
        'portpvlan',
        sa.Column('port_id', sa.String(length=36),
                  sa.ForeignKey('ports.id', ondelete='CASCADE'),
                  primary_key=True),
        sa.Column('pvlan_type',
                  sa.Enum(*pvlan_const.PVLAN_TYPES,
                          name='pvlan_type_enum'),
                  nullable=False),
        sa.Column('pvlan_community', sa.String(255), nullable=True))
