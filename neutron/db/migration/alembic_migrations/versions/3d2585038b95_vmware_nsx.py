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

"""VMware NSX rebranding

Revision ID: 3d2585038b95
Revises: 157a5d299379
Create Date: 2014-02-11 18:18:34.319031

"""

# revision identifiers, used by Alembic.
revision = '3d2585038b95'
down_revision = '157a5d299379'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin'
]

from alembic import op

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.rename_table('nvp_network_bindings', 'tz_network_bindings')
    op.rename_table('nvp_multi_provider_networks', 'multi_provider_networks')

    engine = op.get_bind().engine
    if engine.name == 'postgresql':
        op.execute("ALTER TYPE nvp_network_bindings_binding_type "
                   "RENAME TO tz_network_bindings_binding_type;")


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    engine = op.get_bind().engine
    if engine.name == 'postgresql':
        op.execute("ALTER TYPE tz_network_bindings_binding_type "
                   "RENAME TO nvp_network_bindings_binding_type;")

    op.rename_table('multi_provider_networks', 'nvp_multi_provider_networks')
    op.rename_table('tz_network_bindings', 'nvp_network_bindings')
