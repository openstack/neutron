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

"""FWaaS Havana-2 model

Revision ID: 39cf3f799352
Revises: e6b16a30d97
Create Date: 2013-07-10 16:16:51.302943

"""

# revision identifiers, used by Alembic.
revision = '39cf3f799352'
down_revision = 'e6b16a30d97'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.services.firewall.fwaas_plugin.FirewallPlugin',
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

firewallrules_action = sa.Enum('allow', 'deny', name='firewallrules_action')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('firewall_rules')
    firewallrules_action.drop(op.get_bind(), checkfirst=False)
    op.drop_table('firewalls')
    op.drop_table('firewall_policies')


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'firewall_policies',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.Column('shared', sa.Boolean(), autoincrement=False, nullable=True),
        sa.Column('audited', sa.Boolean(), autoincrement=False,
                  nullable=True),
        sa.PrimaryKeyConstraint('id'))
    op.create_table(
        'firewalls', sa.Column('tenant_id', sa.String(length=255),
                               nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.Column('shared', sa.Boolean(), autoincrement=False, nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), autoincrement=False,
                  nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('firewall_policy_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['firewall_policy_id'],
                                ['firewall_policies.id'],
                                name='firewalls_ibfk_1'),
        sa.PrimaryKeyConstraint('id'))
    op.create_table(
        'firewall_rules',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.Column('firewall_policy_id', sa.String(length=36), nullable=True),
        sa.Column('shared', sa.Boolean(), autoincrement=False,
                  nullable=True),
        sa.Column('protocol', sa.String(length=24), nullable=True),
        sa.Column('ip_version', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('source_ip_address', sa.String(length=46), nullable=True),
        sa.Column('destination_ip_address', sa.String(length=46),
                  nullable=True),
        sa.Column('source_port_range_min', sa.Integer(), nullable=True),
        sa.Column('source_port_range_max', sa.Integer(), nullable=True),
        sa.Column('destination_port_range_min', sa.Integer(), nullable=True),
        sa.Column('destination_port_range_max', sa.Integer(), nullable=True),
        sa.Column('action', firewallrules_action, nullable=True),
        sa.Column('enabled', sa.Boolean(), autoincrement=False,
                  nullable=True),
        sa.Column('position', sa.Integer(), autoincrement=False,
                  nullable=True),
        sa.ForeignKeyConstraint(['firewall_policy_id'],
                                ['firewall_policies.id'],
                                name='firewall_rules_ibfk_1'),
        sa.PrimaryKeyConstraint('id'))
