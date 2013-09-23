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

"""nec-pf-port-del

Revision ID: 1064e98b7917
Revises: 3d6fae8b70b0
Create Date: 2013-09-24 05:33:54.602618

"""

# revision identifiers, used by Alembic.
revision = '1064e98b7917'
down_revision = '3d6fae8b70b0'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nec.nec_plugin.NECPluginV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.alter_column('packetfilters', 'in_port',
                    existing_type=sa.String(length=36),
                    nullable=True)
    op.create_foreign_key(
        'packetfilters_ibfk_2',
        source='packetfilters', referent='ports',
        local_cols=['in_port'], remote_cols=['id'],
        ondelete='CASCADE')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_constraint('packetfilters_ibfk_2', 'packetfilters', 'foreignkey')
    op.alter_column('packetfilters', 'in_port',
                    existing_type=sa.String(length=36),
                    nullable=False)
