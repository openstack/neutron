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

"""floatingip_status

Revision ID: 2eeaf963a447
Revises: f44ab9871cd6
Create Date: 2014-01-14 11:58:13.754747

"""

# revision identifiers, used by Alembic.
revision = '2eeaf963a447'
down_revision = 'f44ab9871cd6'

# This migration is applied to all L3 capable plugins

migration_for_plugins = [
    'neutron.plugins.bigswitch.plugin.NeutronRestProxyV2',
    'neutron.plugins.brocade.NeutronPlugin.BrocadePluginV2',
    'neutron.plugins.cisco.network_plugin.PluginV2',
    'neutron.plugins.cisco.n1kv.n1kv_neutron_plugin.N1kvNeutronPluginV2',
    'neutron.plugins.embrane.plugins.embrane_ovs_plugin.EmbraneOvsPlugin',
    'neutron.plugins.hyperv.hyperv_neutron_plugin.HyperVNeutronPlugin',
    'neutron.plugins.ibm.sdnve_neutron_plugin.SdnvePluginV2',
    'neutron.plugins.linuxbridge.lb_neutron_plugin.LinuxBridgePluginV2',
    'neutron.plugins.metaplugin.meta_neutron_plugin.MetaPluginV2',
    'neutron.plugins.mlnx.mlnx_plugin.MellanoxEswitchPlugin',
    'neutron.plugins.midonet.plugin.MidonetPluginV2',
    'neutron.plugins.ml2.plugin.Ml2Plugin',
    'neutron.plugins.nec.nec_plugin.NECPluginV2',
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.nuage.plugin.NuagePlugin',
    'neutron.plugins.oneconvergence.plugin.OneConvergencePluginV2',
    'neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2',
    'neutron.plugins.plumgrid.plumgrid_plugin.plumgrid_plugin.'
    'NeutronPluginPLUMgridV2',
    'neutron.plugins.ryu.ryu_neutron_plugin.RyuNeutronPluginV2',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin',
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.add_column('floatingips',
                  sa.Column('last_known_router_id',
                            sa.String(length=36),
                            nullable=True))
    op.add_column('floatingips',
                  sa.Column('status',
                            sa.String(length=16),
                            nullable=True))


def downgrade(active_plugins=None, options=None):
    pass