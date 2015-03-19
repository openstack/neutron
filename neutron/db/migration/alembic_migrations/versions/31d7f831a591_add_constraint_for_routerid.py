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

"""add constraint for routerid

Revision ID: 31d7f831a591
Revises: 37f322991f59
Create Date: 2014-02-26 06:47:16.494393

"""

# revision identifiers, used by Alembic.
revision = '31d7f831a591'
down_revision = '37f322991f59'

from alembic import op

from neutron.db import migration

TABLE_NAME = 'routerl3agentbindings'
PK_NAME = 'pk_routerl3agentbindings'


def upgrade():
    # In order to sanitize the data during migration,
    # the current records in the table need to be verified
    # and all the duplicate records which violate the PK
    # constraint need to be removed.
    context = op.get_context()
    if context.bind.dialect.name in ('postgresql', 'ibm_db_sa'):
        op.execute('DELETE FROM %(table)s WHERE id in ('
                   'SELECT %(table)s.id FROM %(table)s LEFT OUTER JOIN '
                   '(SELECT MIN(id) as id, router_id, l3_agent_id '
                   ' FROM %(table)s GROUP BY router_id, l3_agent_id) AS temp '
                   'ON %(table)s.id = temp.id WHERE temp.id is NULL);'
                   % {'table': TABLE_NAME})
    else:
        op.execute('DELETE %(table)s FROM %(table)s LEFT OUTER JOIN '
                   '(SELECT MIN(id) as id, router_id, l3_agent_id '
                   ' FROM %(table)s GROUP BY router_id, l3_agent_id) AS temp '
                   'ON %(table)s.id = temp.id WHERE temp.id is NULL;'
                   % {'table': TABLE_NAME})

    op.drop_column(TABLE_NAME, 'id')

    with migration.remove_fks_from_table(TABLE_NAME):
        # DB2 doesn't support nullable column in primary key
        if context.bind.dialect.name == 'ibm_db_sa':
            op.alter_column(
                table_name=TABLE_NAME,
                column_name='router_id',
                nullable=False
            )
            op.alter_column(
                table_name=TABLE_NAME,
                column_name='l3_agent_id',
                nullable=False
            )

        op.create_primary_key(
            name=PK_NAME,
            table_name=TABLE_NAME,
            cols=['router_id', 'l3_agent_id']
        )
