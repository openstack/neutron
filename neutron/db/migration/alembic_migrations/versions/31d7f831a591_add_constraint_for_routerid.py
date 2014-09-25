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
import sqlalchemy as sa
from sqlalchemy.engine import reflection

TABLE_NAME = 'routerl3agentbindings'
PK_NAME = 'pk_routerl3agentbindings'

fk_names = {'postgresql':
            {'router_id':
                'routerl3agentbindings_router_id_fkey',
             'l3_agent_id':
                'routerl3agentbindings_l3_agent_id_fkey'},
            'mysql':
            {'router_id':
                'routerl3agentbindings_ibfk_2',
             'l3_agent_id':
                'routerl3agentbindings_ibfk_1'}}


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


def downgrade():

    context = op.get_context()
    dialect = context.bind.dialect.name

    # Drop the existed foreign key constraints
    # In order to perform primary key changes
    db2fks = {}
    if dialect == 'ibm_db_sa':
        # NOTE(mriedem): In DB2 the foreign key names are randomly generated
        # if you didn't originally explicitly name them, so the name is like
        # SQLxxxxx where the suffix is a random integer.  Therefore we go
        # through and just drop all of the foreign keys and save them so we
        # can re-create them later after the primary key is dropped.
        inspector = reflection.Inspector.from_engine(op.get_bind().engine)
        db2fks = inspector.get_foreign_keys(TABLE_NAME)
        for fk in db2fks:
            op.drop_constraint(
                name=fk.get('name'),
                table_name=TABLE_NAME,
                type_='foreignkey'
            )
    else:
        op.drop_constraint(
            name=fk_names[dialect]['l3_agent_id'],
            table_name=TABLE_NAME,
            type_='foreignkey'
        )
        op.drop_constraint(
            name=fk_names[dialect]['router_id'],
            table_name=TABLE_NAME,
            type_='foreignkey'
        )

    op.drop_constraint(
        name=PK_NAME,
        table_name=TABLE_NAME,
        type_='primary'
    )

    op.add_column(
        TABLE_NAME,
        sa.Column('id', sa.String(32))
    )

    if dialect == 'ibm_db_sa':
        # DB2 doesn't support nullable column in primary key
        op.alter_column(
            table_name=TABLE_NAME,
            column_name='id',
            nullable=False
        )

    op.create_primary_key(
        name=PK_NAME,
        table_name=TABLE_NAME,
        cols=['id']
    )

    # Restore the foreign key constraints
    if dialect == 'ibm_db_sa':
        for fk in db2fks:
            op.create_foreign_key(
                name=fk.get('name'),
                source=TABLE_NAME,
                referent=fk.get('referred_table'),
                local_cols=fk.get('constrained_columns'),
                remote_cols=fk.get('referred_columns'),
                ondelete='CASCADE'
            )
    else:
        op.create_foreign_key(
            name=fk_names[dialect]['router_id'],
            source=TABLE_NAME,
            referent='routers',
            local_cols=['router_id'],
            remote_cols=['id'],
            ondelete='CASCADE'
        )

        op.create_foreign_key(
            name=fk_names[dialect]['l3_agent_id'],
            source=TABLE_NAME,
            referent='agents',
            local_cols=['l3_agent_id'],
            remote_cols=['id'],
            ondelete='CASCADE'
        )
