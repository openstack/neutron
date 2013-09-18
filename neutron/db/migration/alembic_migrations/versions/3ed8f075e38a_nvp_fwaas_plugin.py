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

"""nvp fwaas plugin

Revision ID: 3ed8f075e38a
Revises: 338d7508968c
Create Date: 2013-09-13 19:14:25.509033

"""

# revision identifiers, used by Alembic.
revision = '3ed8f075e38a'
down_revision = '338d7508968c'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'vcns_firewall_rule_bindings',
        sa.Column('rule_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('rule_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['rule_id'], ['firewall_rules.id'], ),
        sa.PrimaryKeyConstraint('rule_id', 'edge_id')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('vcns_firewall_rule_bindings')
