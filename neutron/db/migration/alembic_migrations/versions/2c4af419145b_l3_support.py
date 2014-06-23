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

"""l3_support

Revision ID: 2c4af419145b
Revises: folsom
Create Date: 2013-03-11 19:26:45.697774

"""

# revision identifiers, used by Alembic.
revision = '2c4af419145b'
down_revision = 'folsom'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.bigswitch.plugin.NeutronRestProxyV2',
    'neutron.plugins.hyperv.hyperv_neutron_plugin.HyperVNeutronPlugin',
    'neutron.plugins.midonet.plugin.MidonetPluginV2',
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin',
    'neutron.plugins.embrane.plugins.embrane_ovs_plugin.EmbraneOvsPlugin',
]

from neutron.db import migration
from neutron.db.migration.alembic_migrations import common_ext_ops


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    common_ext_ops.upgrade_l3()


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    common_ext_ops.downgrade_l3()
