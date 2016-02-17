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

"""standardattributes migration

Revision ID: 8a6d8bdae39
Revises: 1b294093239c
Create Date: 2015-09-10 03:12:04.012457

"""

# revision identifiers, used by Alembic.
revision = '8a6d8bdae39'
down_revision = '1b294093239c'
depends_on = ('32e5974ada25',)

from alembic import op
import sqlalchemy as sa


# basic model of the tables with required field for migration
TABLES = ('ports', 'networks', 'subnets', 'subnetpools', 'securitygroups',
          'floatingips', 'routers', 'securitygrouprules')
TABLE_MODELS = [
    (table, sa.Table(table, sa.MetaData(),
                     sa.Column('id', sa.String(length=36), nullable=False),
                     sa.Column('standard_attr_id', sa.BigInteger(),
                               nullable=True)))
    for table in TABLES
]

standardattrs = sa.Table(
    'standardattributes', sa.MetaData(),
    sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
    sa.Column('resource_type', sa.String(length=255), nullable=False))


def upgrade():
    generate_records_for_existing()
    for table, model in TABLE_MODELS:
        # add constraint(s) now that everything is populated on that table.
        # note that some MariaDB versions will *not* allow the ALTER to
        # NOT NULL on a column that has an FK constraint, so we set NOT NULL
        # first, then the FK constraint.
        op.alter_column(table, 'standard_attr_id', nullable=False,
                        existing_type=sa.BigInteger(), existing_nullable=True,
                        existing_server_default=False)
        op.create_foreign_key(
            constraint_name=None, source_table=table,
            referent_table='standardattributes',
            local_cols=['standard_attr_id'], remote_cols=['id'],
            ondelete='CASCADE')
        op.create_unique_constraint(
            constraint_name='uniq_%s0standard_attr_id' % table,
            table_name=table, columns=['standard_attr_id'])


def generate_records_for_existing():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    with session.begin(subtransactions=True):
        for table, model in TABLE_MODELS:
            for row in session.query(model):
                # NOTE(kevinbenton): without this disabled, pylint complains
                # about a missing 'dml' argument.
                #pylint: disable=no-value-for-parameter
                res = session.execute(
                    standardattrs.insert().values(resource_type=table))
                session.execute(
                    model.update().values(
                        standard_attr_id=res.inserted_primary_key[0]).where(
                            model.c.id == row[0]))
    # this commit is necessary to allow further operations
    session.commit()
    return values
