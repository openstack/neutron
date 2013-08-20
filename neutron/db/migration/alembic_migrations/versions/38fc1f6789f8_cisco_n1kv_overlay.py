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

"""Cisco N1KV overlay support

Revision ID: 38fc1f6789f8
Revises: 1efb85914233
Create Date: 2013-08-20 18:31:16.158387

"""

revision = '38fc1f6789f8'
down_revision = '1efb85914233'

migration_for_plugins = [
    'neutron.plugins.cisco.network_plugin.PluginV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.alter_column('cisco_network_profiles', 'segment_type',
                    existing_type=sa.Enum('vlan', 'overlay', 'trunk',
                                          'multi-segment'),
                    existing_nullable=False)


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.alter_column('cisco_network_profiles', 'segment_type',
                    existing_type=sa.Enum('vlan', 'vxlan', 'trunk',
                                          'multi-segment'),
                    existing_nullable=False)
