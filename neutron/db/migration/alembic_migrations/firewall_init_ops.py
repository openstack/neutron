# Copyright 2014 OpenStack Foundation
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

# Initial schema operations for firewall service plugin


from alembic import op
import sqlalchemy as sa


action_types = sa.Enum('allow', 'deny', name='firewallrules_action')


def upgrade():
    op.create_table(
        'firewall_policies',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.Column('shared', sa.Boolean(), nullable=True),
        sa.Column('audited', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'firewalls',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.Column('shared', sa.Boolean(), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=True),
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
        sa.Column('shared', sa.Boolean(), nullable=True),
        sa.Column('protocol', sa.String(length=40), nullable=True),
        sa.Column('ip_version', sa.Integer(), nullable=False),
        sa.Column('source_ip_address', sa.String(length=46), nullable=True),
        sa.Column('destination_ip_address', sa.String(length=46),
                  nullable=True),
        sa.Column('source_port_range_min', sa.Integer(), nullable=True),
        sa.Column('source_port_range_max', sa.Integer(), nullable=True),
        sa.Column('destination_port_range_min', sa.Integer(), nullable=True),
        sa.Column('destination_port_range_max', sa.Integer(), nullable=True),
        sa.Column('action', action_types, nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('position', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['firewall_policy_id'],
                                ['firewall_policies.id'],
                                name='firewall_rules_ibfk_1'),
        sa.PrimaryKeyConstraint('id'))
