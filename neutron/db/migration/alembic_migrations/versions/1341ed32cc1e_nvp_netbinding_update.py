# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

"""nvp_net_binding

Revision ID: 1341ed32cc1e
Revises: 4692d074d587
Create Date: 2013-02-26 01:28:29.182195

"""

# revision identifiers, used by Alembic.
revision = '1341ed32cc1e'
down_revision = '4692d074d587'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin'
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.alter_column('nvp_network_bindings', 'tz_uuid',
                    name='phy_uuid',
                    existing_type=sa.String(36),
                    existing_nullable=True)
    op.alter_column('nvp_network_bindings', 'binding_type',
                    type_=sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                                  name='nvp_network_bindings_binding_type'),
                    existing_nullable=True)


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.alter_column('nvp_network_bindings', 'phy_uuid',
                    name='tz_uuid',
                    existing_type=sa.String(36),
                    existing_nullable=True)
    op.alter_column('nvp_network_bindings', 'binding_type',
                    type_=sa.Enum('flat', 'vlan', 'stt', 'gre',
                                  name='nvp_network_bindings_binding_type'),
                    existing_nullable=True)
