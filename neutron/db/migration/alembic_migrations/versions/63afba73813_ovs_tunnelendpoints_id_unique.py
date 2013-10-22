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

"""Add unique constraint for id column of TunnelEndpoint

Revision ID: 63afba73813
Revises: 3c6e57a23db4
Create Date: 2013-04-30 13:53:31.717450

"""

# revision identifiers, used by Alembic.
revision = '63afba73813'
down_revision = '3c6e57a23db4'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2',
]

from alembic import op

from neutron.db import migration


CONSTRAINT_NAME = 'uniq_ovs_tunnel_endpoints0id'
TABLE_NAME = 'ovs_tunnel_endpoints'


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_unique_constraint(
        name=CONSTRAINT_NAME,
        source=TABLE_NAME,
        local_cols=['id']
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_constraint(
        CONSTRAINT_NAME,
        TABLE_NAME,
        type_='unique'
    )
