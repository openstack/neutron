# Copyright 2021 Huawei, Inc.
# All rights reserved.
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

"""add Local IP tables

Revision ID: 76df7844a8c6
Revises: e981acd076d3
Create Date: 2021-08-05 14:04:01.380941

"""

from alembic import op
from neutron_lib.db import constants as db_const
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '76df7844a8c6'
down_revision = 'e981acd076d3'


def upgrade():
    op.create_table(
        'local_ips',
        sa.Column('id', sa.String(
                  length=db_const.UUID_FIELD_SIZE),
                  primary_key=True),
        sa.Column('standard_attr_id', sa.BigInteger(),
                  sa.ForeignKey('standardattributes.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('name', sa.String(length=db_const.NAME_FIELD_SIZE)),
        sa.Column('project_id', sa.String(
                  length=db_const.PROJECT_ID_FIELD_SIZE),
                  index=True),
        sa.Column('local_port_id', sa.String(
                  length=db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey('ports.id'),
                  nullable=False),
        sa.Column('network_id', sa.String(
                  length=db_const.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('local_ip_address', sa.String(
                  length=db_const.IP_ADDR_FIELD_SIZE),
                  nullable=False),
        sa.Column('ip_mode', sa.String(length=32),
                  nullable=False),
        sa.UniqueConstraint('standard_attr_id')
    )

    op.create_table(
        'local_ip_associations',
        sa.Column('local_ip_id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey('local_ips.id'),
                  primary_key=True),
        sa.Column('fixed_port_id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey('ports.id', ondelete='CASCADE'),
                  primary_key=True),
        sa.Column('fixed_ip', sa.String(length=db_const.IP_ADDR_FIELD_SIZE),
                  nullable=False),
    )
