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

"""LBaaS add status description

Revision ID: 2032abe8edac
Revises: 477a4488d3f4
Create Date: 2013-06-24 06:51:47.308545

"""

# revision identifiers, used by Alembic.
revision = '2032abe8edac'
down_revision = '477a4488d3f4'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.services.loadbalancer.plugin.LoadBalancerPlugin',
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

ENTITIES = ['vips', 'pools', 'members', 'healthmonitors']


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    for entity in ENTITIES:
        op.add_column(entity, sa.Column('status_description', sa.String(255)))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    for entity in ENTITIES:
        op.drop_column(entity, 'status_description')
