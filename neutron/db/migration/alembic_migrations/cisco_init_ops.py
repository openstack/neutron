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

network_profile_type = sa.Enum('vlan', 'vxlan', name='network_profile_type')


def upgrade():
    op.create_table(
        'cisco_policy_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'cisco_network_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('segment_type', segment_type, nullable=False),
        sa.Column('sub_type', sa.String(length=255), nullable=True),
        sa.Column('segment_range', sa.String(length=255), nullable=True),
        sa.Column('multicast_ip_index', sa.Integer(), nullable=True,
                  server_default='0'),
        sa.Column('multicast_ip_range', sa.String(length=255), nullable=True),
        sa.Column('physical_network', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'cisco_n1kv_vxlan_allocations',
        sa.Column('vxlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False,
                  server_default=sa.sql.false()),
        sa.Column('network_profile_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_profile_id'],
                                ['cisco_network_profiles.id'],
                                ondelete='CASCADE',
                                name='cisco_n1kv_vxlan_allocations_ibfk_1'),
        sa.PrimaryKeyConstraint('vxlan_id'))

    op.create_table(
        'cisco_n1kv_vlan_allocations',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), autoincrement=False,
                  nullable=False, server_default=sa.sql.false()),
        sa.Column('network_profile_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'vlan_id'),
        sa.ForeignKeyConstraint(['network_profile_id'],
                                ['cisco_network_profiles.id'],
                                ondelete='CASCADE',
                                name='cisco_n1kv_vlan_allocations_ibfk_1'))

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
        'cisco_n1kv_profile_bindings',
        sa.Column('profile_type', profile_type, nullable=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=False,
                  server_default='TENANT_ID_NOT_SET'),
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

    op.create_table(
        'cisco_csr_identifier_map',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('ipsec_site_conn_id', sa.String(length=36),
                  primary_key=True),
        sa.Column('csr_tunnel_id', sa.Integer(), nullable=False),
        sa.Column('csr_ike_policy_id', sa.Integer(), nullable=False),
        sa.Column('csr_ipsec_policy_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['ipsec_site_conn_id'],
                                ['ipsec_site_connections.id'],
                                ondelete='CASCADE')
    )

    op.create_table(
        'cisco_ml2_apic_host_links',
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('ifname', sa.String(length=64), nullable=False),
        sa.Column('ifmac', sa.String(length=32), nullable=True),
        sa.Column('swid', sa.String(length=32), nullable=False),
        sa.Column('module', sa.String(length=32), nullable=False),
        sa.Column('port', sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint('host', 'ifname'))

    op.create_table(
        'cisco_ml2_apic_names',
        sa.Column('neutron_id', sa.String(length=36), nullable=False),
        sa.Column('neutron_type', sa.String(length=32), nullable=False),
        sa.Column('apic_name', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('neutron_id', 'neutron_type'))

    op.create_table(
        'cisco_ml2_apic_contracts',
        sa.Column('tenant_id', sa.String(length=255), index=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id']),
        sa.PrimaryKeyConstraint('router_id'))

    op.create_table(
        'cisco_hosting_devices',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('complementary_id', sa.String(length=36), nullable=True),
        sa.Column('device_id', sa.String(length=255), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('management_port_id', sa.String(length=36), nullable=True),
        sa.Column('protocol_port', sa.Integer(), nullable=True),
        sa.Column('cfg_agent_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.ForeignKeyConstraint(['cfg_agent_id'], ['agents.id'], ),
        sa.ForeignKeyConstraint(['management_port_id'], ['ports.id'],
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'cisco_port_mappings',
        sa.Column('logical_resource_id', sa.String(length=36), nullable=False),
        sa.Column('logical_port_id', sa.String(length=36), nullable=False),
        sa.Column('port_type', sa.String(length=32), nullable=True),
        sa.Column('network_type', sa.String(length=32), nullable=True),
        sa.Column('hosting_port_id', sa.String(length=36), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), autoincrement=False,
                  nullable=True),
        sa.ForeignKeyConstraint(['hosting_port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['logical_port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('logical_resource_id', 'logical_port_id')
    )
    op.create_table(
        'cisco_router_mappings',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('auto_schedule', sa.Boolean(), nullable=False),
        sa.Column('hosting_device_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['hosting_device_id'],
                                ['cisco_hosting_devices.id'],
                                ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id')
    )
    op.create_table(
        'cisco_ml2_n1kv_policy_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('vsm_ip', sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint('id', 'vsm_ip'),
    )

    op.create_table(
        'cisco_ml2_n1kv_network_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('segment_type', network_profile_type, nullable=False),
        sa.Column('segment_range', sa.String(length=255), nullable=True),
        sa.Column('multicast_ip_index', sa.Integer(), nullable=True),
        sa.Column('multicast_ip_range', sa.String(length=255), nullable=True),
        sa.Column('sub_type', sa.String(length=255), nullable=True),
        sa.Column('physical_network', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'cisco_ml2_n1kv_port_bindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
    )

    op.create_table(
        'cisco_ml2_n1kv_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('segmentation_id', sa.Integer(), autoincrement=False),
        sa.Column('profile_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['profile_id'],
                                ['cisco_ml2_n1kv_network_profiles.id']),
        sa.PrimaryKeyConstraint('network_id')
    )

    op.create_table(
        'cisco_ml2_n1kv_vxlan_allocations',
        sa.Column('vxlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.Column('network_profile_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_profile_id'],
                                ['cisco_ml2_n1kv_network_profiles.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('vxlan_id')
    )

    op.create_table(
        'cisco_ml2_n1kv_vlan_allocations',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), autoincrement=False,
                  nullable=False),
        sa.Column('network_profile_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_profile_id'],
                                ['cisco_ml2_n1kv_network_profiles.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('physical_network', 'vlan_id')
    )
    op.create_table(
        'cisco_ml2_n1kv_profile_bindings',
        sa.Column('profile_type', profile_type, nullable=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=False,
                  server_default='tenant_id_not_set'),
        sa.Column('profile_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('tenant_id', 'profile_id')
    )
    op.create_table(
        'ml2_ucsm_port_profiles',
        sa.Column('vlan_id', sa.Integer(), nullable=False),
        sa.Column('profile_id', sa.String(length=64), nullable=False),
        sa.Column('created_on_ucs', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('vlan_id')
    )
