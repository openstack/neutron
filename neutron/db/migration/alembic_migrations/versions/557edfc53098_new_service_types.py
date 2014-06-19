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

"""New service types framework (service providers)

Revision ID: 557edfc53098
Revises: 52c5e4a18807
Create Date: 2013-06-29 21:10:41.283358

"""

# revision identifiers, used by Alembic.
revision = '557edfc53098'
down_revision = '52c5e4a18807'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.services.loadbalancer.plugin.LoadBalancerPlugin',
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.create_table(
        'providerresourceassociations',
        sa.Column('provider_name', sa.String(length=255), nullable=False),
        sa.Column('resource_id', sa.String(length=36),
                  nullable=False, unique=True),
    )

    for table in ('servicedefinitions', 'servicetypes'):
        op.execute("DROP TABLE IF EXISTS %s" % table)


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.create_table(
        'servicetypes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255)),
        sa.Column('name', sa.String(255)),
        sa.Column('description', sa.String(255)),
        sa.Column('default', sa.Boolean(), nullable=False, default=False),
        sa.Column('num_instances', sa.Integer, default=0),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'servicedefinitions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('service_class', sa.String(255)),
        sa.Column('plugin', sa.String(255)),
        sa.Column('driver', sa.String(255)),
        sa.Column('service_type_id', sa.String(36),
                  sa.ForeignKey('servicetypes.id',
                                ondelete='CASCADE')),
        sa.PrimaryKeyConstraint('id', 'service_class')
    )
    op.drop_table('providerresourceassociations')
