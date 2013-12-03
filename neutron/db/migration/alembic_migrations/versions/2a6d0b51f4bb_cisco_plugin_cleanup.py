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

"""cisco plugin cleanup

Revision ID: 2a6d0b51f4bb
Revises: 1d76643bcec4
Create Date: 2013-01-17 22:24:37.730466

"""

# revision identifiers, used by Alembic.
revision = '2a6d0b51f4bb'
down_revision = '1d76643bcec4'

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

    op.drop_table(u'portprofile_bindings')
    op.drop_table(u'portprofiles')
    op.drop_table(u'port_bindings')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        u'port_bindings',
        sa.Column(u'id', sa.Integer(), autoincrement=True,
                  nullable=False),
        sa.Column(u'port_id', sa.String(255), nullable=False),
        sa.Column(u'blade_intf_dn', sa.String(255), nullable=False),
        sa.Column(u'portprofile_name', sa.String(255),
                  nullable=True),
        sa.Column(u'vlan_name', sa.String(255), nullable=True),
        sa.Column(u'vlan_id', sa.Integer(), nullable=True),
        sa.Column(u'qos', sa.String(255), nullable=True),
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'vif_id', sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint(u'id')
    )
    op.create_table(
        u'portprofiles',
        sa.Column(u'uuid', sa.String(255), nullable=False),
        sa.Column(u'name', sa.String(255), nullable=True),
        sa.Column(u'vlan_id', sa.Integer(), nullable=True),
        sa.Column(u'qos', sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint(u'uuid')
    )
    op.create_table(
        u'portprofile_bindings',
        sa.Column(u'id', sa.String(255), nullable=False),
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'port_id', sa.String(255), nullable=True),
        sa.Column(u'portprofile_id', sa.String(255), nullable=True),
        sa.Column(u'default', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['portprofile_id'], ['portprofiles.uuid'], ),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ),
        sa.PrimaryKeyConstraint(u'id')
    )
