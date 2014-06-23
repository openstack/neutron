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

"""DB support for service types

Revision ID: 48b6f43f7471
Revises: 5a875d0e5c
Create Date: 2013-01-07 13:47:29.093160

"""

# revision identifiers, used by Alembic.
revision = '48b6f43f7471'
down_revision = '5a875d0e5c'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    '*'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        u'servicetypes',
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'name', sa.String(255), nullable=True),
        sa.Column(u'description', sa.String(255), nullable=True),
        sa.Column(u'default', sa.Boolean(),
                  autoincrement=False, nullable=False),
        sa.Column(u'num_instances', sa.Integer(),
                  autoincrement=False, nullable=True),
        sa.PrimaryKeyConstraint(u'id'))
    op.create_table(
        u'servicedefinitions',
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'service_class', sa.String(length=255),
                  nullable=False),
        sa.Column(u'plugin', sa.String(255), nullable=True),
        sa.Column(u'driver', sa.String(255), nullable=True),
        sa.Column(u'service_type_id', sa.String(36),
                  nullable=False),
        sa.ForeignKeyConstraint(['service_type_id'], [u'servicetypes.id'],
                                name=u'servicedefinitions_ibfk_1'),
        sa.PrimaryKeyConstraint(u'id', u'service_class', u'service_type_id'))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table(u'servicedefinitions')
    op.drop_table(u'servicetypes')
