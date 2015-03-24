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

"""nuage_kilo_migrate

Revision ID: 57dd745253a6
Revises: 2b801560a332
Create Date: 2015-02-12 18:32:27.343786

"""

# revision identifiers, used by Alembic.
revision = '57dd745253a6'
down_revision = '2b801560a332'

from alembic import op
import sqlalchemy as sa

CONSTRAINT_NAME_NR = 'uniq_nuage_net_partition_router_mapping0nuage_router_id'
CONSTRAINT_NAME_NS = 'uniq_nuage_subnet_l2dom_mapping0nuage_subnet_id'


def upgrade():
    op.add_column('nuage_net_partition_router_mapping',
        sa.Column('nuage_rtr_rd', sa.String(length=36), nullable=True))
    op.add_column('nuage_net_partition_router_mapping',
        sa.Column('nuage_rtr_rt', sa.String(length=36), nullable=True))
    op.add_column('nuage_net_partitions',
        sa.Column('isolated_zone', sa.String(length=64), nullable=True))
    op.add_column('nuage_net_partitions',
        sa.Column('shared_zone', sa.String(length=64), nullable=True))
    op.add_column('nuage_subnet_l2dom_mapping',
        sa.Column('nuage_managed_subnet', sa.Boolean(), nullable=True))
    op.create_unique_constraint(
        name=CONSTRAINT_NAME_NR,
        source='nuage_net_partition_router_mapping',
        local_cols=['nuage_router_id'])
    op.create_unique_constraint(
        name=CONSTRAINT_NAME_NS,
        source='nuage_subnet_l2dom_mapping',
        local_cols=['nuage_subnet_id'])
