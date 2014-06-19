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

"""Cisco plugin db cleanup part II

Revision ID: 263772d65691
Revises: 35c7c198ddea
Create Date: 2013-07-29 02:31:26.646343

"""

# revision identifiers, used by Alembic.
revision = '263772d65691'
down_revision = '35c7c198ddea'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.cisco.network_plugin.PluginV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.rename_table('credentials', 'cisco_credentials')
    op.rename_table('nexusport_bindings', 'cisco_nexusport_bindings')
    op.rename_table('qoss', 'cisco_qos_policies')

    op.drop_table('cisco_vlan_ids')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'cisco_vlan_ids',
        sa.Column('vlan_id', sa.Integer, nullable=False),
        sa.Column('vlan_used', sa.Boolean),
        sa.PrimaryKeyConstraint('vlan_id'),
    )

    op.rename_table('cisco_credentials', 'credentials')
    op.rename_table('cisco_nexusport_bindings', 'nexusport_bindings')
    op.rename_table('cisco_qos_policies', 'qoss')
