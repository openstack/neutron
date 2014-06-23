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

"""Support routing table configuration on Router

Revision ID: 1c33fa3cd1a1
Revises: 45680af419f9
Create Date: 2013-01-17 14:35:09.386975

"""

# revision identifiers, used by Alembic.
revision = '1c33fa3cd1a1'
down_revision = '45680af419f9'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2',
    'neutron.plugins.linuxbridge.lb_neutron_plugin.LinuxBridgePluginV2',
    'neutron.plugins.metaplugin.meta_neutron_plugin.MetaPluginV2',
    'neutron.plugins.ml2.plugin.Ml2Plugin',
    'neutron.plugins.nec.nec_plugin.NECPluginV2',
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.ryu.ryu_neutron_plugin.RyuNeutronPluginV2',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin',
    'neutron.plugins.oneconvergence.plugin.OneConvergencePluginV2',
    'neutron.plugins.cisco.network_plugin.PluginV2',
    'neutron.plugins.bigswitch.plugin.NeutronRestProxyV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.rename_table(
        'routes',
        'subnetroutes',
    )
    op.create_table(
        'routerroutes',
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.Column(
            'nexthop', sa.String(length=64), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ['router_id'], ['routers.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('destination', 'nexthop', 'router_id')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.rename_table(
        'subnetroutes',
        'routes',
    )
    op.drop_table('routerroutes')
