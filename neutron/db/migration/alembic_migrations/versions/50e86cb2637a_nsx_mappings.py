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

    op.create_table('neutron_nsx_port_mappings',
                    sa.Column('neutron_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nsx_port_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nsx_switch_id', sa.String(length=36),
                              nullable=True),
                    sa.ForeignKeyConstraint(['neutron_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('neutron_id'))

    op.execute("INSERT INTO neutron_nsx_port_mappings SELECT quantum_id as "
               "neutron_id, nvp_id as nsx_port_id, null as nsx_switch_id from"
               " quantum_nvp_port_mapping")
    op.drop_table('quantum_nvp_port_mapping')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    # Restore table to pre-icehouse version
    op.create_table('quantum_nvp_port_mapping',
                    sa.Column('quantum_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nvp_id', sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['quantum_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('quantum_id'))
    op.execute("INSERT INTO quantum_nvp_port_mapping SELECT neutron_id as "
               "quantum_id, nsx_port_id as nvp_id from"
               " neutron_nsx_port_mappings")
    op.drop_table('neutron_nsx_port_mappings')
