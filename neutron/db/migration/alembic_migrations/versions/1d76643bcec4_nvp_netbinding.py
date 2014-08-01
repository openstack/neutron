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

"""nvp_netbinding

Revision ID: 1d76643bcec4
Revises: 3cb5d900c5de
Create Date: 2013-01-15 07:36:10.024346

"""

# revision identifiers, used by Alembic.
revision = '1d76643bcec4'
down_revision = '3cb5d900c5de'

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

nvp_network_bindings_binding_type = sa.Enum(
    'flat', 'vlan', 'stt', 'gre', name='nvp_network_bindings_binding_type')


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'nvp_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('binding_type', nvp_network_bindings_binding_type,
                  nullable=False),
        sa.Column('tz_uuid', sa.String(length=36), nullable=True),
        sa.Column('vlan_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('nvp_network_bindings')
    nvp_network_bindings_binding_type.drop(op.get_bind(), checkfirst=False)
