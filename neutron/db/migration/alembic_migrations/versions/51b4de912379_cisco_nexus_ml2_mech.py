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

"""Cisco Nexus ML2 mechanism driver

Revision ID: 51b4de912379
Revises: 66a59a7f516
Create Date: 2013-08-20 15:31:40.553634

"""

# revision identifiers, used by Alembic.
revision = '51b4de912379'
down_revision = '66a59a7f516'

migration_for_plugins = [
    'neutron.plugins.ml2.plugin.Ml2Plugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'cisco_ml2_nexusport_bindings',
        sa.Column('binding_id', sa.Integer(), nullable=False),
        sa.Column('port_id', sa.String(length=255), nullable=True),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('switch_ip', sa.String(length=255), nullable=True),
        sa.Column('instance_id', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('binding_id'),
    )
    op.create_table(
        'cisco_ml2_credentials',
        sa.Column('credential_id', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('credential_name', sa.String(length=255), nullable=False),
        sa.Column('user_name', sa.String(length=255), nullable=True),
        sa.Column('password', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('tenant_id', 'credential_name'),
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('cisco_ml2_credentials')
    op.drop_table('cisco_ml2_nexusport_bindings')
