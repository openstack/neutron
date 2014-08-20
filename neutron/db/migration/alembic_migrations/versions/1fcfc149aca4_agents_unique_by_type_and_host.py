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

"""Add a unique constraint on (agent_type, host) columns to prevent a race
condition when an agent entry is 'upserted'.

Revision ID: 1fcfc149aca4
Revises: e197124d4b9
Create Date: 2013-11-27 18:35:28.148680

"""

revision = '1fcfc149aca4'
down_revision = 'e197124d4b9'

migration_for_plugins = [
    'neutron.plugins.brocade.NeutronPlugin.BrocadePluginV2',
    'neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2',
    'neutron.plugins.linuxbridge.lb_neutron_plugin.LinuxBridgePluginV2',
    'neutron.plugins.ml2.plugin.Ml2Plugin',
    'neutron.plugins.nec.nec_plugin.NECPluginV2',
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin',
    'neutron.services.loadbalancer.plugin.LoadBalancerPlugin',
    'neutron.plugins.ibm.sdnve_neutron_plugin.SdnvePluginV2',
    'neutron.plugins.oneconvergence.plugin.OneConvergencePluginV2',
    'neutron.plugins.mlnx.mlnx_plugin.MellanoxEswitchPlugin',
]

from alembic import op

from neutron.db import migration


TABLE_NAME = 'agents'
UC_NAME = 'uniq_agents0agent_type0host'


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_unique_constraint(
        name=UC_NAME,
        source=TABLE_NAME,
        local_cols=['agent_type', 'host']
    )


def downgrade(active_plugins=None, options=None):
    pass