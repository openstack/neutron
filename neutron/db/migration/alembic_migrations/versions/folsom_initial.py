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
    'bigswitch': 'neutron.plugins.bigswitch.plugin.NeutronRestProxyV2',
    'brocade': 'neutron.plugins.brocade.NeutronPlugin.BrocadePluginV2',
    'cisco': 'neutron.plugins.cisco.network_plugin.PluginV2',
    'lbr': 'neutron.plugins.linuxbridge.lb_neutron_plugin.LinuxBridgePluginV2',
    'meta': 'neutron.plugins.metaplugin.meta_neutron_plugin.MetaPluginV2',
    'ml2': 'neutron.plugins.ml2.plugin.Ml2Plugin',
    'mlnx': 'neutron.plugins.mlnx.mlnx_plugin.MellanoxEswitchPlugin',
    'nec': 'neutron.plugins.nec.nec_plugin.NECPluginV2',
    'nvp': 'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'ocnvsd': 'neutron.plugins.oneconvergence.plugin.OneConvergencePluginV2',
    'ovs': 'neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2',
    'plumgrid': 'neutron.plugins.plumgrid.plumgrid_plugin.plumgrid_plugin.'
                'NeutronPluginPLUMgridV2',
    'ryu': 'neutron.plugins.ryu.ryu_neutron_plugin.RyuNeutronPluginV2',
    'ibm': 'neutron.plugins.ibm.sdnve_neutron_plugin.SdnvePluginV2',
}

L3_CAPABLE = [
    PLUGINS['lbr'],
    PLUGINS['meta'],
    PLUGINS['ml2'],
    PLUGINS['mlnx'],
    PLUGINS['nec'],
    PLUGINS['ocnvsd'],
    PLUGINS['ovs'],
    PLUGINS['ryu'],
    PLUGINS['brocade'],
    PLUGINS['plumgrid'],
    PLUGINS['ibm'],
]

FOLSOM_QUOTA = [
    PLUGINS['lbr'],
    PLUGINS['ml2'],
    PLUGINS['nvp'],
    PLUGINS['ocnvsd'],
    PLUGINS['ovs'],
]


# revision identifiers, used by Alembic.
revision = 'folsom'
down_revision = None

from alembic import op
import sqlalchemy as sa

from neutron.db import migration
from neutron.db.migration.alembic_migrations import common_ext_ops
# NOTE: This is a special migration that creates a Folsom compatible database.


def upgrade(active_plugins=None, options=None):
    # general model
    upgrade_base()

    if migration.should_run(active_plugins, L3_CAPABLE):
        common_ext_ops.upgrade_l3()

    if migration.should_run(active_plugins, FOLSOM_QUOTA):
        common_ext_ops.upgrade_quota(options)

    if PLUGINS['lbr'] in active_plugins:
        upgrade_linuxbridge()
    elif PLUGINS['ovs'] in active_plugins:
        upgrade_ovs()
    elif PLUGINS['cisco'] in active_plugins:
        upgrade_cisco()
        # Cisco plugin imports OVS models too
        upgrade_ovs()
    elif PLUGINS['meta'] in active_plugins:
        upgrade_meta()
    elif PLUGINS['nec'] in active_plugins:
        upgrade_nec()
    elif PLUGINS['ryu'] in active_plugins:
        upgrade_ryu()
    elif PLUGINS['brocade'] in active_plugins:
        upgrade_brocade()
        # Brocade plugin imports linux bridge models too
        upgrade_linuxbridge()


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
        sa.Column('network_id', sa.String(length=36), nullable=False),
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


def upgrade_brocade():
    op.create_table(
        'brocadenetworks',
        sa.Column('id', sa.Integer(), autoincrement=False, nullable=False),
        sa.Column('vlan', sa.String(10)),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'brocadeports',
        sa.Column('port_id', sa.String(36), nullable=False),
        sa.Column('network_id', sa.String(36)),
        sa.Column('admin_state_up', sa.Boolean()),
        sa.Column('physical_interface', sa.String(36)),
        sa.Column('vlan_id', sa.String(10)),
        sa.Column('tenant_id', sa.String(36)),
        sa.PrimaryKeyConstraint('port_id')
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
        sa.Column('vlan_id', sa.Integer()),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade(active_plugins=None, options=None):
    if PLUGINS['lbr'] in active_plugins:
        downgrade_linuxbridge()
    elif PLUGINS['ovs'] in active_plugins:
        downgrade_ovs()
    elif PLUGINS['cisco'] in active_plugins:
        # Cisco plugin imports OVS models too
        downgrade_ovs()
        downgrade_cisco()
    elif PLUGINS['meta'] in active_plugins:
        downgrade_meta()
    elif PLUGINS['nec'] in active_plugins:
        downgrade_nec()
    elif PLUGINS['ryu'] in active_plugins:
        downgrade_ryu()
    elif PLUGINS['brocade'] in active_plugins:
        # Brocade plugin imports linux bridge models too
        downgrade_brocade()
        downgrade_linuxbridge()

    if migration.should_run(active_plugins, FOLSOM_QUOTA):
        common_ext_ops.downgrade_quota(options)

    if migration.should_run(active_plugins, L3_CAPABLE):
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


def downgrade_brocade():
    op.drop_table('brocadenetworks')
    op.drop_table('brocadeports')


def downgrade_cisco():
    drop_tables(
        'nexusport_bindings',
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
