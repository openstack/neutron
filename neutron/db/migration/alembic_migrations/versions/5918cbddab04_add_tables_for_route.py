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

"""add tables for router rules support

Revision ID: 5918cbddab04
Revises: 3cbf70257c28
Create Date: 2013-06-16 02:20:07.024752

"""

# revision identifiers, used by Alembic.
revision = '5918cbddab04'
down_revision = '3cbf70257c28'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.bigswitch.plugin.NeutronRestProxyV2'
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table('routerrules',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('source', sa.String(length=64), nullable=False),
                    sa.Column('destination', sa.String(length=64),
                              nullable=False),
                    sa.Column('action', sa.String(length=10), nullable=False),
                    sa.Column('router_id', sa.String(length=36),
                              nullable=True),
                    sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('nexthops',
                    sa.Column('rule_id', sa.Integer(), nullable=False),
                    sa.Column('nexthop', sa.String(length=64), nullable=False),
                    sa.ForeignKeyConstraint(['rule_id'], ['routerrules.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('rule_id', 'nexthop'))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('nexthops')
    op.drop_table('routerrules')
