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

"""ml2 binding:profile

Revision ID: 157a5d299379
Revises: 50d5ba354c23
Create Date: 2014-02-13 23:48:25.147279

"""

# revision identifiers, used by Alembic.
revision = '157a5d299379'
down_revision = '50d5ba354c23'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():
    if migration.schema_has_table('ml2_port_bindings'):
        op.add_column('ml2_port_bindings',
                      sa.Column('profile', sa.String(length=4095),
                                nullable=False, server_default=''))
