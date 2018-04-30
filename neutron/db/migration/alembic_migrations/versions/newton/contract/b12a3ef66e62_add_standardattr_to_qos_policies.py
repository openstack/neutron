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

from alembic import op
import sqlalchemy as sa

"""add standardattr to qos policies

Revision ID: b12a3ef66e62
Revises: 3b935b28e7a0
Create Date: 2016-08-18 14:10:30.021055

"""

# revision identifiers, used by Alembic.
revision = 'b12a3ef66e62'
down_revision = '3b935b28e7a0'
depends_on = ('67daae611b6e',)


# basic model of the tables with required field for migration
TABLE = 'qos_policies'


TABLE_MODEL = sa.Table(TABLE, sa.MetaData(),
                       sa.Column('id', sa.String(length=36), nullable=False),
                       sa.Column('description', sa.String(length=255),
                                 nullable=True),
                       sa.Column('standard_attr_id', sa.BigInteger(),
                                 nullable=True))

standardattrs = sa.Table(
    'standardattributes', sa.MetaData(),
    sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
    sa.Column('resource_type', sa.String(length=255), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=True))


def upgrade():
    generate_records_for_existing()
    # add the constraint now that everything is populated on that table
    op.alter_column(TABLE, 'standard_attr_id', nullable=False,
                    existing_type=sa.BigInteger(), existing_nullable=True,
                    existing_server_default=False)
    op.create_unique_constraint(
        constraint_name='uniq_%s0standard_attr_id' % TABLE,
        table_name=TABLE, columns=['standard_attr_id'])
    op.drop_column(TABLE, 'description')
    op.create_foreign_key(
        constraint_name=None, source_table=TABLE,
        referent_table='standardattributes',
        local_cols=['standard_attr_id'], remote_cols=['id'],
        ondelete='CASCADE')


def generate_records_for_existing():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    with session.begin(subtransactions=True):
        for row in session.query(TABLE_MODEL):
            # NOTE(kevinbenton): without this disabled, pylint complains
            # about a missing 'dml' argument.
            # pylint: disable=no-value-for-parameter
            res = session.execute(
                standardattrs.insert().values(resource_type=TABLE,
                                              description=row[1])
            )
            session.execute(
                TABLE_MODEL.update().values(
                    standard_attr_id=res.inserted_primary_key[0]).where(
                        TABLE_MODEL.c.id == row[0])
            )
    # this commit is necessary to allow further operations
    session.commit()
    return values
