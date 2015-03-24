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

"""L3 DVR SNAT mapping

Revision ID: 41662e32bce2
Revises: 4dbe243cd84d
Create Date: 2014-12-22 16:48:56.922833

"""

# revision identifiers, used by Alembic.
revision = '41662e32bce2'
down_revision = '4dbe243cd84d'

from alembic import op
from sqlalchemy.engine import reflection

from neutron.db import migration


TABLE_NAME = 'csnat_l3_agent_bindings'


def upgrade():
    inspector = reflection.Inspector.from_engine(op.get_bind())
    prev_pk_const = inspector.get_pk_constraint(TABLE_NAME)
    prev_pk_name = prev_pk_const.get('name')

    with migration.remove_fks_from_table(TABLE_NAME):
        op.drop_constraint(name=prev_pk_name,
                           table_name=TABLE_NAME,
                           type_='primary')

        op.create_primary_key(name=None,
                              table_name=TABLE_NAME,
                              cols=['router_id', 'l3_agent_id'])
