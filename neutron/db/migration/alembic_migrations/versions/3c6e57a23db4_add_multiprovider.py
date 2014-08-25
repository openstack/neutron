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

"""add multiprovider

Revision ID: 3c6e57a23db4
Revises: 86cf4d88bd3
Create Date: 2013-07-10 12:43:35.769283

"""

# revision identifiers, used by Alembic.
revision = '3c6e57a23db4'
down_revision = '86cf4d88bd3'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin'
]

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from neutron.db import migration


def get_enum():
    engine = op.get_bind().engine
    # In PostgreSQL types created separately, so if type was already created in
    # 1341ed32cc1e_nvp_netbinding_update it should be created one time.
    # Use parameter create_type=False for that.
    if engine.name == 'postgresql':
        return postgresql.ENUM('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                               name='nvp_network_bindings_binding_type',
                               create_type=False)
    else:
        return sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                       name='nvp_network_bindings_binding_type')


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'nvp_multi_provider_networks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))
    op.create_table('rename_nvp_network_bindings',
                    sa.Column('network_id', sa.String(length=36),
                              primary_key=True),
                    sa.Column('binding_type', get_enum(),
                              nullable=False, primary_key=True),
                    sa.Column('phy_uuid', sa.String(36), primary_key=True,
                              nullable=True),
                    sa.Column('vlan_id', sa.Integer, primary_key=True,
                              nullable=True, autoincrement=False))
    # copy data from nvp_network_bindings into rename_nvp_network_bindings
    op.execute("INSERT INTO rename_nvp_network_bindings SELECT network_id, "
               "binding_type, phy_uuid, vlan_id from nvp_network_bindings")

    op.drop_table('nvp_network_bindings')
    op.rename_table('rename_nvp_network_bindings', 'nvp_network_bindings')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    # Delete the multi_provider_network entries from nvp_network_bindings
    op.execute("DELETE from nvp_network_bindings WHERE network_id IN "
               "(SELECT network_id from nvp_multi_provider_networks)")
    # create table with previous contains
    op.create_table('rename_nvp_network_bindings',
                    sa.Column('network_id', sa.String(length=36),
                              primary_key=True),
                    sa.Column('binding_type',
                              get_enum(),
                              nullable=False),
                    sa.Column('phy_uuid', sa.String(36),
                              nullable=True),
                    sa.Column('vlan_id', sa.Integer,
                              nullable=True, autoincrement=False))

    # copy data from nvp_network_bindings into rename_nvp_network_bindings
    op.execute("INSERT INTO rename_nvp_network_bindings SELECT network_id, "
               "binding_type, phy_uuid, vlan_id from nvp_network_bindings")

    op.drop_table('nvp_network_bindings')
    op.rename_table('rename_nvp_network_bindings', 'nvp_network_bindings')
    op.drop_table('nvp_multi_provider_networks')
