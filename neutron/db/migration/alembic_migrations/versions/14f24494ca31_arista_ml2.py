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

"""DB Migration for Arista ml2 mechanism driver

Revision ID: 14f24494ca31
Revises: 2a3bae1ceb8
Create Date: 2013-08-15 18:54:16.083640

"""

# revision identifiers, used by Alembic.
revision = '14f24494ca31'
down_revision = '2a3bae1ceb8'

# Change to ['*'] if this migration applies to all plugins

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
        'arista_provisioned_nets',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('segmentation_id', sa.Integer(),
                  autoincrement=False, nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'arista_provisioned_vms',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('vm_id', sa.String(length=255), nullable=True),
        sa.Column('host_id', sa.String(length=255), nullable=True),
        sa.Column('port_id', sa.String(length=36), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'arista_provisioned_tenants',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id'))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('arista_provisioned_tenants')
    op.drop_table('arista_provisioned_vms')
    op.drop_table('arista_provisioned_nets')
