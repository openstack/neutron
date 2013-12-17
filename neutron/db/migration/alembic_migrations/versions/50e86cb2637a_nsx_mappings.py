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

"""nsx_mappings

Revision ID: 50e86cb2637a
Revises: havana
Create Date: 2013-10-26 14:37:30.012149

"""

# revision identifiers, used by Alembic.
revision = '50e86cb2637a'
down_revision = '1fcfc149aca4'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    # Update table for port/lswitchport mappings
    op.rename_table('neutron_nvp_port_mapping', 'neutron_nsx_port_mappings')
    op.add_column(
        'neutron_nsx_port_mappings',
        sa.Column('nsx_switch_id', sa.String(length=36), nullable=True))
    op.alter_column(
        'neutron_nsx_port_mappings', 'nvp_id',
        new_column_name='nsx_port_id',
        existing_nullable=True,
        existing_type=sa.String(length=36))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    # Restore table to pre-icehouse version
    op.drop_column('neutron_nsx_port_mappings', 'nsx_switch_id')
    op.alter_column(
        'neutron_nsx_port_mappings', 'nsx_port_id',
        new_column_name='nvp_id',
        existing_nullable=True,
        existing_type=sa.String(length=36))
    op.rename_table('neutron_nsx_port_mappings', 'neutron_nvp_port_mapping')
