# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

"""ml2 binding:vif_details

Revision ID: 50d5ba354c23
Revises: 27cc183af192
Create Date: 2014-02-11 23:21:59.577972

"""

# revision identifiers, used by Alembic.
revision = '50d5ba354c23'
down_revision = '27cc183af192'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.ml2.plugin.Ml2Plugin'
]

from alembic import context
from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.add_column('ml2_port_bindings',
                  sa.Column('vif_details', sa.String(length=4095),
                            nullable=False, server_default=''))
    migr_context = context.get_context()
    with context.begin_transaction():
        for value in ('true', 'false'):
            migr_context.execute(
                "UPDATE ml2_port_bindings SET"
                " vif_details = '{\"port_filter\": %(value)s}'"
                " WHERE cap_port_filter = %(value)s" % {'value': value})
    op.drop_column('ml2_port_bindings', 'cap_port_filter')


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.add_column('ml2_port_bindings',
                  sa.Column('cap_port_filter', sa.Boolean(),
                            nullable=False, default=False))
    migr_context = context.get_context()
    with context.begin_transaction():
        migr_context.execute(
            "UPDATE ml2_port_bindings SET"
            " cap_port_filter = true"
            " WHERE vif_details LIKE '%\"port_filter\": true%'")
    op.drop_column('ml2_port_bindings', 'vif_details')
