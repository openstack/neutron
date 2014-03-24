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

"""NEC Rename quantum_id to neutron_id

Revision ID: 538732fa21e1
Revises: 2447ad0e9585
Create Date: 2014-03-04 05:43:33.660601

"""

# revision identifiers, used by Alembic.
revision = '538732fa21e1'
down_revision = '2447ad0e9585'

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

    for table in ['ofctenantmappings', 'ofcnetworkmappings',
                  'ofcportmappings', 'ofcfiltermappings',
                  'ofcroutermappings',
                  ]:
        op.alter_column(table, 'quantum_id',
                        new_column_name='neutron_id',
                        existing_type=sa.String(length=36),
                        existing_nullable=False)


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    for table in ['ofctenantmappings', 'ofcnetworkmappings',
                  'ofcportmappings', 'ofcfiltermappings',
                  'ofcroutermappings',
                  ]:
        op.alter_column(table, 'neutron_id',
                        new_column_name='quantum_id',
                        existing_type=sa.String(length=36),
                        existing_nullable=False)
