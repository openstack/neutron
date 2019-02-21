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

# Initial operations for core resources
from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'networks',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=True),
        sa.Column('shared', sa.Boolean(), nullable=True),
        sa.Column('mtu', sa.Integer(), nullable=True),
        sa.Column('vlan_transparent', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ports',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('mac_address', sa.String(length=32), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('device_id', sa.String(length=255), nullable=False),
        sa.Column('device_owner', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id']),
        sa.UniqueConstraint('network_id', 'mac_address',
                            name='uniq_ports0network_id0mac_address'),
        sa.PrimaryKeyConstraint('id'),
        sa.Index(op.f('ix_ports_network_id_device_owner'), 'network_id',
                 'device_owner'),
        sa.Index(op.f('ix_ports_network_id_mac_address'), 'network_id',
                 'mac_address'))

    op.create_table(
        'subnets',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('ip_version', sa.Integer(), nullable=False),
        sa.Column('cidr', sa.String(length=64), nullable=False),
        sa.Column('gateway_ip', sa.String(length=64), nullable=True),
        sa.Column('enable_dhcp', sa.Boolean(), nullable=True),
        sa.Column('shared', sa.Boolean(), nullable=True),
        sa.Column('ipv6_ra_mode',
                  sa.Enum('slaac', 'dhcpv6-stateful', 'dhcpv6-stateless',
                          name='ipv6_ra_modes'),
                  nullable=True),
        sa.Column('ipv6_address_mode',
                  sa.Enum('slaac', 'dhcpv6-stateful', 'dhcpv6-stateless',
                          name='ipv6_address_modes'),
                  nullable=True),
        sa.Column('subnetpool_id', sa.String(length=36), nullable=True,
                  index=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'], ),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'dnsnameservers',
        sa.Column('address', sa.String(length=128), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('address', 'subnet_id'))

    op.create_table(
        'ipallocationpools',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=True),
        sa.Column('first_ip', sa.String(length=64), nullable=False),
        sa.Column('last_ip', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'subnetroutes',
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.Column('nexthop', sa.String(length=64), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('destination', 'nexthop', 'subnet_id'))

    op.create_table(
        'ipallocations',
        sa.Column('port_id', sa.String(length=36), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('ip_address', 'subnet_id', 'network_id'))

    op.create_table(
        'ipavailabilityranges',
        sa.Column('allocation_pool_id', sa.String(length=36), nullable=False),
        sa.Column('first_ip', sa.String(length=64), nullable=False),
        sa.Column('last_ip', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['allocation_pool_id'],
                                ['ipallocationpools.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('allocation_pool_id', 'first_ip', 'last_ip'),
        sa.UniqueConstraint(
            'first_ip', 'allocation_pool_id',
            name='uniq_ipavailabilityranges0first_ip0allocation_pool_id'),
        sa.UniqueConstraint(
            'last_ip', 'allocation_pool_id',
            name='uniq_ipavailabilityranges0last_ip0allocation_pool_id'))

    op.create_table(
        'networkdhcpagentbindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('dhcp_agent_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['dhcp_agent_id'], ['agents.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'dhcp_agent_id'))
