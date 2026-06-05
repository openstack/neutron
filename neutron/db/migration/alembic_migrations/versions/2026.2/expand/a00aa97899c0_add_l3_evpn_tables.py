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

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# Add tables for EVPN L3 instances and advertised ports
#
# Revision ID: a00aa97899c0
# Revises: bdae3a00c493
# Create Date: 2026-05-18 14:47:45.797641

# revision identifiers, used by Alembic.
revision = 'a00aa97899c0'
down_revision = 'bdae3a00c493'


def upgrade():
    inspector = sa.inspect(op.get_bind())
    constraints = inspector.get_unique_constraints('ports')
    if not any(c['name'] == 'uniq_ports0id0network_id'
               for c in constraints):
        op.create_unique_constraint(
            'uniq_ports0id0network_id', 'ports', ['id', 'network_id'])

    migration.create_table_if_not_exists(
        'vni_allocations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vni', sa.Integer(), nullable=False),
        sa.Column('physnet', sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('vni', 'physnet',
                            name='uniq_vni_allocations0vni0physnet'),
    )
    migration.create_table_if_not_exists(
        'vlan_allocations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vlan_id', sa.Integer(), nullable=False),
        sa.Column('physnet', sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('vlan_id', 'physnet',
                            name='uniq_vlan_allocations0vlan_id0physnet'),
    )
    migration.create_table_if_not_exists(
        'vni_vlan_mapping',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vni_allocation_id', sa.String(length=36), nullable=False),
        sa.Column('vlan_allocation_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['vni_allocation_id'],
                                ['vni_allocations.id'],
                                ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['vlan_allocation_id'],
                                ['vlan_allocations.id'],
                                ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('vni_allocation_id'),
        sa.UniqueConstraint('vlan_allocation_id'),
    )
    migration.create_table_if_not_exists(
        'evpn_l3_instances',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('mapping_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['mapping_id'], ['vni_vlan_mapping.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'),
        sa.UniqueConstraint('mapping_id'),
    )
    migration.create_table_if_not_exists(
        'evpn_networks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['router_id'],
                                ['evpn_l3_instances.router_id'],
                                ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('network_id'),
    )
    migration.create_table_if_not_exists(
        'evpn_advertised_ports',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id', 'network_id'],
                                ['ports.id', 'ports.network_id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['network_id'],
                                ['evpn_networks.network_id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
    )
