# Copyright (c) 2019 Red Hat, Inc.
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


"""conntrack helper

Revision ID: 63fd95af7dcd
Revises: 9bfad3f1e780
Create Date: 2019-03-26 15:37:20.996070

"""

# revision identifiers, used by Alembic.
revision = '63fd95af7dcd'
down_revision = '9bfad3f1e780'


def upgrade():
    op.create_table(
        'conntrack_helpers',
        sa.Column('id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  nullable=False, primary_key=True),
        sa.Column('router_id', sa.String(length=db_const.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('protocol', sa.String(length=40), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('helper', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.UniqueConstraint(
            'router_id', 'protocol', 'port', 'helper',
            name='uniq_conntrack_helpers0router_id0protocol0port0helper')
    )
