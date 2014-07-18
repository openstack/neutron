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

"""set_server_default

Revision ID: 5446f2a45467
Revises: 2db5203cb7a9
Create Date: 2014-07-07 18:31:30.384522

"""

# revision identifiers, used by Alembic.
revision = '5446f2a45467'
down_revision = '2db5203cb7a9'


from alembic import op
import sqlalchemy as sa
import sqlalchemy.sql


from neutron.plugins.cisco.common import cisco_constants

PLUGINS = {
    'brocade': 'neutron.plugins.brocade.NeutronPlugin.BrocadePluginV2',
    'cisco': 'neutron.plugins.cisco.network_plugin.PluginV2',
    'ml2': 'neutron.plugins.ml2.plugin.Ml2Plugin',
    'mlnx': 'neutron.plugins.mlnx.mlnx_plugin.MellanoxEswitchPlugin',
    'vmware': [
        'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
        'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
        'neutron.plugins.vmware.plugin.NsxPlugin',
        'neutron.plugins.vmware.plugin.NsxServicePlugin',
    ],
    'agents': [
        'neutron.plugins.linuxbridge.lb_neutron_plugin.LinuxBridgePluginV2',
        'neutron.plugins.nec.nec_plugin.NECPluginV2',
        'neutron.plugins.oneconvergence.plugin.OneConvergencePluginV2',
        'neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2',
        'neutron.plugins.ibm.sdnve_neutron_plugin.SdnvePluginV2',
        'neutron.services.loadbalancer.plugin.LoadBalancerPlugin',
    ],
}


def upgrade(active_plugins=None, options=None):
    run(active_plugins, True)


def downgrade(active_plugins=None, options=None):
    run(active_plugins, None)


def run(active_plugins, default):
    if PLUGINS['ml2'] in active_plugins:
        set_default_ml2(default)
    if PLUGINS['mlnx'] in active_plugins:
        set_default_agents(default)
        set_default_mlnx(default)
    if PLUGINS['brocade'] in active_plugins:
        set_default_agents(default)
        set_default_brocade(default)
    if PLUGINS['cisco'] in active_plugins:
        set_default_cisco(default)
    if set(PLUGINS['vmware']) & set(active_plugins):
            set_default_vmware(default)
            set_default_agents(default)
    if set(PLUGINS['agents']) & set(active_plugins):
        set_default_agents(default)


def set_default_brocade(default):
    if default:
        default = ''
    op.alter_column('brocadeports', 'port_id',
                    server_default=default, existing_type=sa.String(36))


def set_default_mlnx(default):
    if default:
        default = sqlalchemy.sql.false()
    op.alter_column('segmentation_id_allocation', 'allocated',
                    server_default=default, existing_nullable=False,
                    existing_type=sa.Boolean)


def set_default_cisco(default):
    profile_binding_default = (cisco_constants.TENANT_ID_NOT_SET
                               if default else None)
    profile_default = '0' if default else None
    if default:
        default = sqlalchemy.sql.false()
    op.alter_column('cisco_n1kv_profile_bindings', 'tenant_id',
                    existing_type=sa.String(length=36),
                    server_default=profile_binding_default,
                    existing_nullable=False)
    op.alter_column('cisco_network_profiles', 'multicast_ip_index',
                    server_default=profile_default, existing_type=sa.Integer)
    op.alter_column('cisco_n1kv_vlan_allocations', 'allocated',
                    existing_type=sa.Boolean,
                    server_default=default, existing_nullable=False)
    op.alter_column('cisco_n1kv_vxlan_allocations', 'allocated',
                    existing_type=sa.Boolean,
                    server_default=default, existing_nullable=False)


def set_default_vmware(default=None):
    if default:
        default = sqlalchemy.sql.false()
    op.alter_column('nsxrouterextattributess', 'service_router',
                    server_default=default, existing_nullable=False,
                    existing_type=sa.Boolean)
    op.alter_column('nsxrouterextattributess', 'distributed',
                    server_default=default, existing_nullable=False,
                    existing_type=sa.Boolean)
    op.alter_column('qosqueues', 'default',
                    server_default=default, existing_type=sa.Boolean)


def set_default_agents(default=None):
    if default:
        default = sqlalchemy.sql.true()
    op.alter_column('agents', 'admin_state_up',
                    server_default=default, existing_nullable=False,
                    existing_type=sa.Boolean)


def set_default_ml2(default=None):
    if default:
        default = sqlalchemy.sql.false()
    op.alter_column('ml2_gre_allocations', 'allocated',
                    server_default=default, existing_nullable=False,
                    existing_type=sa.Boolean)
    op.alter_column('ml2_vxlan_allocations', 'allocated',
                    server_default=default, existing_nullable=False,
                    existing_type=sa.Boolean)
