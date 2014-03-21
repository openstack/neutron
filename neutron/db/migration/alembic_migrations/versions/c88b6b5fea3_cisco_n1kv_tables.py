# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation
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

"""Cisco N1KV tables

Revision ID: c88b6b5fea3
Revises: 263772d65691
Create Date: 2013-08-06 15:08:32.651975

"""

# revision identifiers, used by Alembic.
revision = 'c88b6b5fea3'
down_revision = '263772d65691'

migration_for_plugins = [
    'neutron.plugins.cisco.network_plugin.PluginV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

vlan_type = sa.Enum('vlan', 'vxlan', name='vlan_type')
network_type = sa.Enum('network', 'policy', name='network_type')


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_column('cisco_credentials', 'tenant_id')
    op.add_column(
        'cisco_credentials',
        sa.Column('type', sa.String(length=255), nullable=True)
    )
    op.create_table(
        'cisco_policy_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'cisco_n1kv_vmnetworks',
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('port_count', sa.Integer(), autoincrement=False,
                  nullable=True),
        sa.ForeignKeyConstraint(['profile_id'], ['cisco_policy_profiles.id']),
        sa.PrimaryKeyConstraint('name')
    )
    op.create_table(
        'cisco_n1kv_vxlan_allocations',
        sa.Column('vxlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), autoincrement=False,
                  nullable=False),
        sa.PrimaryKeyConstraint('vxlan_id')
    )
    op.create_table(
        'cisco_network_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('segment_type', vlan_type, nullable=False),
        sa.Column('segment_range', sa.String(length=255), nullable=True),
        sa.Column('multicast_ip_index', sa.Integer(), autoincrement=False,
                  nullable=True),
        sa.Column('multicast_ip_range', sa.String(length=255), nullable=True),
        sa.Column('physical_network', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'cisco_n1kv_profile_bindings',
        sa.Column('profile_type', network_type, nullable=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('tenant_id', 'profile_id')
    )
    op.create_table(
        'cisco_n1kv_port_bindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['profile_id'], ['cisco_policy_profiles.id']),
        sa.PrimaryKeyConstraint('port_id')
    )
    op.create_table(
        'cisco_n1kv_vlan_allocations',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id',
                  sa.Integer(),
                  autoincrement=False,
                  nullable=False),
        sa.Column('allocated',
                  sa.Boolean(),
                  autoincrement=False,
                  nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'vlan_id')
    )
    op.create_table(
        'cisco_n1kv_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), autoincrement=False,
                  nullable=True),
        sa.Column('multicast_ip', sa.String(length=32), nullable=True),
        sa.Column('profile_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['profile_id'], ['cisco_network_profiles.id']),
        sa.PrimaryKeyConstraint('network_id')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('cisco_n1kv_network_bindings')
    op.drop_table('cisco_n1kv_vlan_allocations')
    op.drop_table('cisco_n1kv_port_bindings')
    op.drop_table('cisco_n1kv_profile_bindings')
    network_type.drop(op.get_bind(), checkfirst=False)
    op.drop_table('cisco_network_profiles')
    vlan_type.drop(op.get_bind(), checkfirst=False)
    op.drop_table('cisco_n1kv_vxlan_allocations')
    op.drop_table('cisco_n1kv_vmnetworks')
    op.drop_table('cisco_policy_profiles')
    op.drop_column('cisco_credentials', 'type')
    op.add_column(
        'cisco_credentials',
        sa.Column('tenant_id', sa.String(length=255), nullable=False)
    )
