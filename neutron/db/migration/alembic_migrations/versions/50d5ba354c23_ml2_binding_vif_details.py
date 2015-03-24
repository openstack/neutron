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

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():

    if not migration.schema_has_table('ml2_port_bindings'):
        # In the database we are migrating from, the configured plugin
        # did not create the ml2_port_bindings table.
        return

    op.add_column('ml2_port_bindings',
                  sa.Column('vif_details', sa.String(length=4095),
                            nullable=False, server_default=''))
    if op.get_bind().engine.name == 'ibm_db_sa':
        op.execute(
            "UPDATE ml2_port_bindings SET"
            " vif_details = '{\"port_filter\": true}'"
            " WHERE cap_port_filter = 1")
        op.execute(
            "UPDATE ml2_port_bindings SET"
            " vif_details = '{\"port_filter\": false}'"
            " WHERE cap_port_filter = 0")
    else:
        op.execute(
            "UPDATE ml2_port_bindings SET"
            " vif_details = '{\"port_filter\": true}'"
            " WHERE cap_port_filter = true")
        op.execute(
            "UPDATE ml2_port_bindings SET"
            " vif_details = '{\"port_filter\": false}'"
            " WHERE cap_port_filter = false")
    op.drop_column('ml2_port_bindings', 'cap_port_filter')
    if op.get_bind().engine.name == 'ibm_db_sa':
        op.execute("CALL SYSPROC.ADMIN_CMD('REORG TABLE ml2_port_bindings')")
