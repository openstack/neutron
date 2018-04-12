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

from alembic import op
import sqlalchemy as sa

from neutron.db.migration import cli

"""nsxv_vdr_metadata.py

Revision ID: 354db87e3225
Revises: kilo
Create Date: 2015-04-19 14:59:15.102609

"""

# revision identifiers, used by Alembic.
revision = '354db87e3225'
down_revision = 'kilo'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    op.create_table(
        'nsxv_vdr_dhcp_bindings',
        sa.Column('vdr_router_id', sa.String(length=36), nullable=False),
        sa.Column('dhcp_router_id', sa.String(length=36), nullable=False),
        sa.Column('dhcp_edge_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('vdr_router_id'),
        sa.UniqueConstraint(
            'dhcp_router_id',
            name='unique_nsxv_vdr_dhcp_bindings0dhcp_router_id'),
        sa.UniqueConstraint(
            'dhcp_edge_id',
            name='unique_nsxv_vdr_dhcp_bindings0dhcp_edge_id'))
