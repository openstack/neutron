# Copyright 2022 OpenStack Foundation
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

from neutron_lib.db import constants

from neutron.db import migration

"""add router ndp proxy table

Revision ID: 34cf8b009713
Revises: cd9ef14ccf87
Create Date: 2021-12-03 03:57:34.838905

"""

# revision identifiers, used by Alembic.
revision = '34cf8b009713'
down_revision = 'cd9ef14ccf87'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.YOGA]


def upgrade():
    op.create_table(
        'router_ndp_proxy_state',
        sa.Column('router_id', sa.String(length=constants.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('enable_ndp_proxy', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'),
    )
    op.create_table(
        'ndp_proxies',
        sa.Column('project_id', sa.String(
            length=constants.PROJECT_ID_FIELD_SIZE), index=True),
        sa.Column('name', sa.String(length=constants.NAME_FIELD_SIZE),
                  nullable=True),
        sa.Column('id', sa.String(length=constants.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('router_id',
                  sa.String(length=constants.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('port_id',
                  sa.String(length=constants.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('ip_address', sa.String(constants.IP_ADDR_FIELD_SIZE),
                  nullable=False),
        sa.Column('standard_attr_id', sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['standard_attr_id'],
                                ['standardattributes.id'],
                                ondelete='CASCADE'),
        sa.UniqueConstraint('standard_attr_id')
    )
