# Copyright 2020 OpenStack Foundation
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


"""Add standard attributes to address group

Revision ID: 26d1e9f5c766
Revises: a964d94b4677
Create Date: 2020-12-02 17:38:45.331048

"""

# revision identifiers, used by Alembic.
revision = '26d1e9f5c766'
down_revision = 'a964d94b4677'


TABLE = 'address_groups'

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


def generate_records_for_existing():
    session = sa.orm.Session(bind=op.get_bind())
    for row in session.query(TABLE_MODEL):
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


def upgrade():
    op.add_column(TABLE, sa.Column('standard_attr_id', sa.BigInteger(),
                                   nullable=True))
    generate_records_for_existing()

    # add the constraint now that everything is populated on that table
    op.create_foreign_key(
        constraint_name=None, source_table=TABLE,
        referent_table='standardattributes',
        local_cols=['standard_attr_id'], remote_cols=['id'],
        ondelete='CASCADE')
    op.alter_column(TABLE, 'standard_attr_id', nullable=False,
                    existing_type=sa.BigInteger(), existing_nullable=True,
                    existing_server_default=False)
    op.create_unique_constraint(
        constraint_name='uniq_%s0standard_attr_id' % TABLE,
        table_name=TABLE, columns=['standard_attr_id'])
    op.drop_column(TABLE, 'description')


def expand_drop_exceptions():
    """Drop the description column for table address_groups

    Drop the existing description column in address_groups table since
    address_groups are now associated with standard_attributes.
    """

    return {
        sa.Column: ['%s.description' % TABLE]
    }
