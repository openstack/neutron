# Copyright 2014 VMware, Inc.

# All Rights Reserved
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

"""NSX DHCP/metadata support

Revision ID: 1421183d533f
Revises: 50e86cb2637a
Create Date: 2013-10-11 14:33:37.303215

"""

revision = '1421183d533f'
down_revision = '50e86cb2637a'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'lsn',
        sa.Column('net_id',
                  sa.String(length=36), nullable=False),
        sa.Column('lsn_id',
                  sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('lsn_id'))

    op.create_table(
        'lsn_port',
        sa.Column('lsn_port_id',
                  sa.String(length=36), nullable=False),
        sa.Column('lsn_id',
                  sa.String(length=36), nullable=False),
        sa.Column('sub_id',
                  sa.String(length=36), nullable=False, unique=True),
        sa.Column('mac_addr',
                  sa.String(length=32), nullable=False, unique=True),
        sa.ForeignKeyConstraint(['lsn_id'], ['lsn.lsn_id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('lsn_port_id'))
