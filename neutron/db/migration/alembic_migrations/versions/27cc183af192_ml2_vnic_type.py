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

"""ml2_vnic_type

Revision ID: 27cc183af192
Revises: 4ca36cfc898c
Create Date: 2014-02-09 12:19:21.362967

"""

# revision identifiers, used by Alembic.
revision = '27cc183af192'
down_revision = '4ca36cfc898c'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():
    if migration.schema_has_table('ml2_port_bindings'):
        op.add_column('ml2_port_bindings',
                      sa.Column('vnic_type', sa.String(length=64),
                                nullable=False,
                                server_default='normal'))
