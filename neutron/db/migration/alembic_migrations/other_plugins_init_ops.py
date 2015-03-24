# Copyright 2014 OpenStack Foundation
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

# Initial operations for plugins:
# hyper-v
# bigswitch
# metaplugin


from alembic import op
import sqlalchemy as sa


def upgrade():
    # hyper-v
    op.create_table(
        'hyperv_vlan_allocations',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'vlan_id'))

    op.create_table(
        'hyperv_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))

    # metaplugin
    op.create_table(
        'networkflavors',
        sa.Column('flavor', sa.String(length=255), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))

    op.create_table(
        'routerflavors',
        sa.Column('flavor', sa.String(length=255), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'))

    # big switch
    op.create_table(
        'routerrules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=10), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'nexthops',
        sa.Column('rule_id', sa.Integer(), nullable=False),
        sa.Column('nexthop', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['rule_id'], ['routerrules.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('rule_id', 'nexthop'))
