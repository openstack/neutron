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

"""Drop NSX table in favor of the extra_attributes one

Revision ID: 884573acbf1c
Revises: 5589aa32bf80
Create Date: 2013-01-07 13:47:29.093160

"""

revision = '884573acbf1c'
down_revision = '5589aa32bf80'


from alembic import op
import sqlalchemy as sa


def _migrate_data(old_table, new_table):
    engine = op.get_bind().engine
    if engine.name == 'postgresql':
        op.execute(("UPDATE %(new_table)s new_t "
                    "SET distributed = old_t.distributed, "
                    "service_router = old_t.service_router "
                    "FROM %(old_table)s old_t "
                    "WHERE new_t.router_id = old_t.router_id") %
                   {'new_table': new_table, 'old_table': old_table})
    elif engine.name == 'ibm_db_sa':
        op.execute(("UPDATE %(new_table)s new_t "
                    "SET (distributed, service_router) = "
                    "(SELECT old_t.distributed, old_t.service_router "
                    "FROM %(old_table)s old_t "
                    "WHERE new_t.router_id = old_t.router_id)") %
                   {'new_table': new_table, 'old_table': old_table})
    else:
        op.execute(("UPDATE %(new_table)s new_t "
                    "INNER JOIN %(old_table)s as old_t "
                    "ON new_t.router_id = old_t.router_id "
                    "SET new_t.distributed = old_t.distributed, "
                    "new_t.service_router = old_t.service_router") %
                   {'new_table': new_table, 'old_table': old_table})


def upgrade():
    op.add_column('router_extra_attributes',
                  sa.Column('service_router', sa.Boolean(),
                            nullable=False,
                            server_default=sa.sql.false()))
    _migrate_data('router_extra_attributes', 'nsxrouterextattributess')
    op.drop_table('nsxrouterextattributess')
