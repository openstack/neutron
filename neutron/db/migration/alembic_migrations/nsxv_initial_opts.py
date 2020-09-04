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


appliance_sizes_enum = sa.Enum('compact', 'large', 'xlarge', 'quadlarge',
                               name='nsxv_router_bindings_appliance_size')
edge_types_enum = sa.Enum('service', 'vdr',
                          name='nsxv_router_bindings_edge_type')
internal_network_purpose_enum = sa.Enum('inter_edge_net',
                                        name='nsxv_internal_networks_purpose')
internal_edge_purpose_enum = sa.Enum('inter_edge_net',
                                     name='nsxv_internal_edges_purpose')
tz_binding_type_enum = sa.Enum('flat', 'vlan', 'portgroup',
                               name='nsxv_tz_network_bindings_binding_type')
router_types_enum = sa.Enum('shared', 'exclusive',
                            name='nsxv_router_type')


def upgrade():
    op.create_table(
        'nsxv_router_bindings',
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=True),
        sa.Column('lswitch_id', sa.String(length=36), nullable=True),
        sa.Column('appliance_size',
                  appliance_sizes_enum,
                  nullable=True),
        sa.Column('edge_type', edge_types_enum, nullable=True),
        sa.PrimaryKeyConstraint('router_id'))
    op.create_table(
        'nsxv_internal_networks',
        sa.Column('network_purpose', internal_network_purpose_enum,
                  nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_purpose'))
    op.create_table(
        'nsxv_internal_edges',
        sa.Column('ext_ip_address', sa.String(length=64), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.Column('purpose', internal_edge_purpose_enum, nullable=True),
        sa.PrimaryKeyConstraint('ext_ip_address'))
    op.create_table(
        'nsxv_firewall_rule_bindings',
        sa.Column('rule_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('rule_vse_id', sa.String(length=36), nullable=True),
        sa.PrimaryKeyConstraint('rule_id', 'edge_id'))
    op.create_table(
        'nsxv_edge_dhcp_static_bindings',
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('mac_address', sa.String(length=32), nullable=False),
        sa.Column('binding_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('edge_id', 'mac_address'))
    op.create_table(
        'nsxv_edge_vnic_bindings',
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('vnic_index', sa.Integer(), nullable=False),
        sa.Column('tunnel_index', sa.Integer(), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.PrimaryKeyConstraint('edge_id', 'vnic_index', 'tunnel_index'))
    op.create_table(
        'nsxv_spoofguard_policy_network_mappings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))
    op.create_table(
        'nsxv_security_group_section_mappings',
        sa.Column('neutron_id', sa.String(length=36), nullable=False),
        sa.Column('ip_section_id', sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(['neutron_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('neutron_id'))
    op.create_table(
        'nsxv_tz_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('binding_type',
                  tz_binding_type_enum,
                  nullable=False),
        sa.Column('phy_uuid', sa.String(length=36), nullable=True),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False, nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'binding_type', 'phy_uuid',
                                'vlan_id'))
    op.create_table(
        'nsxv_port_vnic_mappings',
        sa.Column('neutron_id', sa.String(length=36), nullable=False),
        sa.Column('nsx_id', sa.String(length=42), nullable=False),
        sa.ForeignKeyConstraint(['neutron_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('neutron_id', 'nsx_id'))
    op.create_table(
        'nsxv_port_index_mappings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('device_id', sa.String(length=255), nullable=False),
        sa.Column('index', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
        sa.UniqueConstraint('device_id', 'index'))
    op.create_table(
        'nsxv_rule_mappings',
        sa.Column('neutron_id', sa.String(length=36), nullable=False),
        sa.Column('nsx_rule_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['neutron_id'], ['securitygrouprules.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('neutron_id', 'nsx_rule_id'))
    op.create_table(
        'nsxv_router_ext_attributes',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('distributed', sa.Boolean(), nullable=False),
        sa.Column('router_type', router_types_enum,
                  default='exclusive', nullable=False),
        sa.Column('service_router', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'))
