# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 New Dream Network, LLC (DreamHost)
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
# @author Mark McClain (DreamHost)

"""folsom initial database

Revision ID: folsom
Revises: None
Create Date: 2012-12-03 09:14:50.579765

"""

PLUGINS = {
    'bigswitch': 'quantum.plugins.bigswitch.plugin.QuantumRestProxyV2',
    'cisco': 'quantum.plugins.cisco.network_plugin.PluginV2',
    'lbr': 'quantum.plugins.linuxbridge.lb_quantum_plugin.LinuxBridgePluginV2',
    'meta': 'quantum.plugins.metaplugin.meta_quantum_plugin.MetaPluginV2',
    'nec': 'quantum.plugins.nec.nec_plugin.NECPluginV2',
    'nvp': (
        'quantum.plugins.nicira.nicira_nvp_plugin.QuantumPlugin.NvpPluginV2'),
    'ovs': 'quantum.plugins.openvswitch.ovs_quantum_plugin.OVSQuantumPluginV2',
    'ryu': 'quantum.plugins.ryu.ryu_quantum_plugin.RyuQuantumPluginV2',
}

L3_CAPABLE = [
    PLUGINS['lbr'],
    PLUGINS['meta'],
    PLUGINS['nec'],
    PLUGINS['ovs'],
    PLUGINS['ryu'],
]

FOLSOM_QUOTA = [
    PLUGINS['lbr'],
    PLUGINS['nvp'],
    PLUGINS['ovs'],
]


# revision identifiers, used by Alembic.
revision = 'folsom'
down_revision = None

from alembic import op
import sqlalchemy as sa

from quantum.db.migration.alembic_migrations import common_ext_ops
# NOTE: This is a special migration that creates a Folsom compatible database.


def upgrade(active_plugin=None, options=None):
    # general model
    upgrade_base()

    if active_plugin in L3_CAPABLE:
        common_ext_ops.upgrade_l3()

    if active_plugin in FOLSOM_QUOTA:
        common_ext_ops.upgrade_quota(options)

    if active_plugin == PLUGINS['lbr']:
        upgrade_linuxbridge()
    elif active_plugin == PLUGINS['ovs']:
        upgrade_ovs()
    elif active_plugin == PLUGINS['cisco']:
        upgrade_cisco()
        # Cisco plugin imports OVS models too
        upgrade_ovs()
    elif active_plugin == PLUGINS['meta']:
        upgrade_meta()
    elif active_plugin == PLUGINS['nec']:
        upgrade_nec()
    elif active_plugin == PLUGINS['ryu']:
        upgrade_ryu()


def upgrade_base():
    op.create_table(
        'networks',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=True),
        sa.Column('shared', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'subnets',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('ip_version', sa.Integer(), nullable=False),
        sa.Column('cidr', sa.String(length=64), nullable=False),
        sa.Column('gateway_ip', sa.String(length=64), nullable=True),
        sa.Column('enable_dhcp', sa.Boolean(), nullable=True),
        sa.Column('shared', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'ports',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('mac_address', sa.String(length=32), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('device_id', sa.String(length=255), nullable=False),
        sa.Column('device_owner', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'dnsnameservers',
        sa.Column('address', sa.String(length=128), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('address', 'subnet_id')
    )

    op.create_table(
        'ipallocations',
        sa.Column('port_id', sa.String(length=36), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('expiration', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('ip_address', 'subnet_id', 'network_id')
    )

    op.create_table(
        'routes',
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.Column('nexthop', sa.String(length=64), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('destination', 'nexthop', 'subnet_id')
    )

    op.create_table(
        'ipallocationpools',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=True),
        sa.Column('first_ip', sa.String(length=64), nullable=False),
        sa.Column('last_ip', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'ipavailabilityranges',
        sa.Column('allocation_pool_id', sa.String(length=36), nullable=False),
        sa.Column('first_ip', sa.String(length=64), nullable=False),
        sa.Column('last_ip', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['allocation_pool_id'],
                                ['ipallocationpools.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('allocation_pool_id', 'first_ip', 'last_ip')
    )


def upgrade_linuxbridge():
    op.create_table(
        'network_states',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'vlan_id')
    )

    op.create_table(
        'network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )


def upgrade_ovs():
    op.create_table(
        'ovs_tunnel_endpoints',
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.Column('id', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('ip_address')
    )

    op.create_table(
        'ovs_tunnel_ips',
        sa.Column('ip_address', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('ip_address')
    )

    op.create_table(
        'ovs_vlan_allocations',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'vlan_id')
    )

    op.create_table(
        'ovs_tunnel_allocations',
        sa.Column('tunnel_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('tunnel_id')
    )

    op.create_table(
        'ovs_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )


def upgrade_meta():
    op.create_table(
        'networkflavors',
        sa.Column('flavor', sa.String(length=255)),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )

    op.create_table(
        'routerflavors',
        sa.Column('flavor', sa.String(length=255)),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id')
    )


def upgrade_nec():
    op.create_table(
        'ofctenants',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'ofcnetworks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'ofcports',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'ofcfilters',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'portinfos',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('datapath_id', sa.String(length=36), nullable=False),
        sa.Column('port_no', sa.Integer(), nullable=False),
        sa.Column('vlan_id', sa.Integer(), nullable=False),
        sa.Column('mac', sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'packetfilters',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(16), nullable=False),
        sa.Column('in_port', sa.String(36), nullable=False),
        sa.Column('src_mac', sa.String(32), nullable=False),
        sa.Column('dst_mac', sa.String(32), nullable=False),
        sa.Column('eth_type', sa.Integer(), nullable=False),
        sa.Column('src_cidr', sa.String(64), nullable=False),
        sa.Column('dst_cidr', sa.String(64), nullable=False),
        sa.Column('protocol', sa.String(16), nullable=False),
        sa.Column('src_port', sa.Integer(), nullable=False),
        sa.Column('dst_port', sa.Integer(), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )


def upgrade_ryu():
    op.create_table(
        'ofp_server',
        sa.Column('id', sa.Integer(), autoincrement=False, nullable=False),
        sa.Column('address', sa.String(255)),
        sa.Column('host_type', sa.String(255)),
        sa.PrimaryKeyConstraint('id')
    )


def upgrade_cisco():
    op.create_table(
        'cisco_vlan_ids',
        sa.Column('vlan_id', sa.Integer(), autoincrement=True),
        sa.Column('vlan_used', sa.Boolean()),
        sa.PrimaryKeyConstraint('vlan_id')
    )

    op.create_table(
        'cisco_vlan_bindings',
        sa.Column('vlan_id', sa.Integer(), autoincrement=True),
        sa.Column('vlan_name', sa.String(255)),
        sa.Column('network_id', sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint('vlan_id')
    )

    op.create_table(
        'portprofiles',
        sa.Column('uuid', sa.String(255), nullable=False),
        sa.Column('name', sa.String(255)),
        sa.Column('vlan_id', sa.Integer()),
        sa.Column('qos', sa.String(255)),
        sa.PrimaryKeyConstraint('uuid')
    )

    op.create_table(
        'portprofile_bindings',
        sa.Column('id', sa.Integer(), autoincrement=True),
        sa.Column('tenant_id', sa.String(255)),
        sa.Column('port_id', sa.String(255), nullable=False),
        sa.Column('portprofile_id', sa.String(255), nullable=False),
        sa.Column('default', sa.Boolean()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ),
        sa.ForeignKeyConstraint(['portprofile_id'], ['portprofiles.uuid'], ),
    )

    op.create_table(
        'qoss',  # yes two S's
        sa.Column('qos_id', sa.String(255)),
        sa.Column('tenant_id', sa.String(255)),
        sa.Column('qos_name', sa.String(255)),
        sa.Column('qos_desc', sa.String(255)),
        sa.PrimaryKeyConstraint('tenant_id', 'qos_name')
    )

    op.create_table(
        'credentials',
        sa.Column('credential_id', sa.String(255)),
        sa.Column('tenant_id', sa.String(255)),
        sa.Column('credential_name', sa.String(255)),
        sa.Column('user_name', sa.String(255)),
        sa.Column('password', sa.String(255)),
        sa.PrimaryKeyConstraint('tenant_id', 'credential_name')
    )

    op.create_table(
        'port_bindings',
        sa.Column('id', sa.Integer(), autoincrement=True),
        sa.Column('port_id', sa.String(255), nullable=False),
        sa.Column('blade_intf_dn', sa.String(255), nullable=False),
        sa.Column('portprofile_name', sa.String(255)),
        sa.Column('vlan_name', sa.String(255)),
        sa.Column('vlan_id', sa.Integer()),
        sa.Column('qos', sa.String(255)),
        sa.Column('tenant_id', sa.String(255)),
        sa.Column('instance_id', sa.String(255)),
        sa.Column('vif_id', sa.String(255)),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'nexusport_bindings',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('port_id', sa.String(255)),
        sa.Column('vlan_id', sa.Integer(255)),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade(active_plugin=None, options=None):
    if active_plugin == PLUGINS['lbr']:
        downgrade_linuxbridge()
    elif active_plugin == PLUGINS['ovs']:
        downgrade_ovs()
    elif active_plugin == PLUGINS['cisco']:
        # Cisco plugin imports OVS models too
        downgrade_ovs()
        downgrade_cisco()
    elif active_plugin == PLUGINS['meta']:
        downgrade_meta()
    elif active_plugin == PLUGINS['nec']:
        downgrade_nec()
    elif active_plugin == PLUGINS['ryu']:
        downgrade_ryu()

    if active_plugin in FOLSOM_QUOTA:
        common_ext_ops.downgrade_quota(options)

    if active_plugin in L3_CAPABLE:
        common_ext_ops.downgrade_l3()

    downgrade_base()


def downgrade_base():
    drop_tables(
        'ipavailabilityranges',
        'ipallocationpools',
        'routes',
        'ipallocations',
        'dnsnameservers',
        'ports',
        'subnets',
        'networks'
    )


def downgrade_linuxbridge():
    drop_tables('network_bindings', 'network_states')


def downgrade_ovs():
    drop_tables(
        'ovs_network_bindings',
        'ovs_tunnel_allocations',
        'ovs_vlan_allocations',
        'ovs_tunnel_ips',
        'ovs_tunnel_endpoints'
    )


def downgrade_meta():
    drop_tables('routerflavors', 'networkflavors')


def downgrade_nec():
    drop_tables(
        'packetfilters',
        'portinfos',
        'ofcfilters',
        'ofcports',
        'ofcnetworks',
        'ofctenants'
    )


def downgrade_ryu():
    op.drop_table('ofp_server')


def downgrade_cisco():
    op.drop_tables(
        'nextport_bindings',
        'port_bindings',
        'credentials',
        'qoss',
        'portprofile_bindings',
        'portprofiles',
        'cisco_vlan_bindings',
        'cisco_vlan_ids'
    )


def drop_tables(*tables):
    for table in tables:
        op.drop_table(table)
