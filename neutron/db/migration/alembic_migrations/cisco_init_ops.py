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

# Initial schema operations for cisco plugin

from alembic import op
import sqlalchemy as sa


segment_type = sa.Enum('vlan', 'overlay', 'trunk', 'multi-segment',
                       name='segment_type')
profile_type = sa.Enum('network', 'policy', name='profile_type')


def upgrade():
    op.create_table(
        'cisco_policy_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'cisco_n1kv_vlan_allocations',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), autoincrement=False,
                  nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'vlan_id'))

    op.create_table(
        'cisco_network_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('segment_type', segment_type, nullable=False),
        sa.Column('sub_type', sa.String(length=255), nullable=True),
        sa.Column('segment_range', sa.String(length=255), nullable=True),
        sa.Column('multicast_ip_index', sa.Integer(), nullable=True),
        sa.Column('multicast_ip_range', sa.String(length=255), nullable=True),
        sa.Column('physical_network', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'cisco_n1kv_vxlan_allocations',
        sa.Column('vxlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('vxlan_id'))

    op.create_table(
        'cisco_credentials',
        sa.Column('credential_id', sa.String(length=255), nullable=True),
        sa.Column('credential_name', sa.String(length=255), nullable=False),
        sa.Column('user_name', sa.String(length=255), nullable=True),
        sa.Column('password', sa.String(length=255), nullable=True),
        sa.Column('type', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('credential_name'))

    op.create_table(
        'cisco_qos_policies',
        sa.Column('qos_id', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('qos_name', sa.String(length=255), nullable=False),
        sa.Column('qos_desc', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('tenant_id', 'qos_name'))

    op.create_table(
        'cisco_nexusport_bindings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('port_id', sa.String(length=255), nullable=True),
        sa.Column('vlan_id', sa.Integer(), nullable=False),
        sa.Column('switch_ip', sa.String(length=255), nullable=False),
        sa.Column('instance_id', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'cisco_n1kv_profile_bindings',
        sa.Column('profile_type', profile_type, nullable=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('tenant_id', 'profile_id'))

    op.create_table(
        'cisco_n1kv_vmnetworks',
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('port_count', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['profile_id'],
                                ['cisco_policy_profiles.id'], ),
        sa.PrimaryKeyConstraint('name'))

    op.create_table(
        'cisco_n1kv_trunk_segments',
        sa.Column('trunk_segment_id', sa.String(length=36), nullable=False),
        sa.Column('segment_id', sa.String(length=36), nullable=False),
        sa.Column('dot1qtag', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['trunk_segment_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('trunk_segment_id', 'segment_id', 'dot1qtag'))

    op.create_table(
        'cisco_provider_networks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=255), nullable=False),
        sa.Column('segmentation_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))

    op.create_table(
        'cisco_n1kv_multi_segments',
        sa.Column('multi_segment_id', sa.String(length=36), nullable=False),
        sa.Column('segment1_id', sa.String(length=36), nullable=False),
        sa.Column('segment2_id', sa.String(length=36), nullable=False),
        sa.Column('encap_profile_name', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['multi_segment_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('multi_segment_id', 'segment1_id',
                                'segment2_id'))

    op.create_table(
        'cisco_n1kv_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), nullable=True),
        sa.Column('multicast_ip', sa.String(length=32), nullable=True),
        sa.Column('profile_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['profile_id'],
                                ['cisco_network_profiles.id']),
        sa.PrimaryKeyConstraint('network_id'))

    op.create_table(
        'cisco_n1kv_port_bindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['profile_id'], ['cisco_policy_profiles.id']),
        sa.PrimaryKeyConstraint('port_id'))
