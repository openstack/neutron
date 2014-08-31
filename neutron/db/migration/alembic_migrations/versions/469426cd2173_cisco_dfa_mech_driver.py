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

"""Cisco DFA Mechanism Driver

Revision ID: 469426cd2173
Revises: 32f3915891fd
Create Date: 2014-06-28 01:13:04.152945

"""

# revision identifiers, used by Alembic.
revision = '469426cd2173'
down_revision = '32f3915891fd'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'cisco_dfa_config_profiles',
        sa.Column('id', sa.String(36)),
        sa.Column('name', sa.String(255)),
        sa.Column('forwarding_mode', sa.String(32)),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'cisco_dfa_config_profile_bindings',
        sa.Column('network_id', sa.String(36)),
        sa.Column('cfg_profile_id', sa.String(36)),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'cfg_profile_id'))

    op.create_table(
        'cisco_dfa_project_cache',
        sa.Column('project_id', sa.String(36)),
        sa.Column('project_name', sa.String(255)),
        sa.PrimaryKeyConstraint('project_id'))


def downgrade(active_plugins=None, options=None):
    op.drop_table('cisco_dfa_project_cache')
    op.drop_table('cisco_dfa_config_profile_bindings')
    op.drop_table('cisco_dfa_config_profiles')
