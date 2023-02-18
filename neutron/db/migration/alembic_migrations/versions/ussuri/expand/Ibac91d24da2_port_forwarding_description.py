# Copyright 2019 OpenStack Foundation
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

import sqlalchemy as sa

from alembic import op

"""port forwarding rule description

Revision ID: Ibac91d24da2
Revises: 263d454a9655
Create Date: 2019-07-13 10:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'Ibac91d24da2'
down_revision = '263d454a9655'

TABLE_NAME = 'portforwardings'

TABLE_MODEL = sa.Table(TABLE_NAME, sa.MetaData(),
                       sa.Column('id', sa.String(length=36), nullable=False),
                       sa.Column('standard_attr_id', sa.BigInteger(),
                                 nullable=True))

STDATTRS_TABLE = sa.Table(
    'standardattributes', sa.MetaData(),
    sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
    sa.Column('resource_type', sa.String(length=255), nullable=False))


def update_existing_records():
    session = sa.orm.Session(bind=op.get_bind())
    for row in session.query(TABLE_MODEL):
        res = session.execute(
            STDATTRS_TABLE.insert().values(resource_type=TABLE_NAME)
        )
        session.execute(
            TABLE_MODEL.update().values(
                standard_attr_id=res.inserted_primary_key[0]).where(
                TABLE_MODEL.c.id == row[0])
        )
    session.commit()


def upgrade():
    op.add_column(TABLE_NAME, sa.Column('standard_attr_id',
                                        sa.BigInteger(),
                                        nullable=True))
    update_existing_records()

    op.alter_column(TABLE_NAME, 'standard_attr_id', nullable=False,
                    existing_type=sa.BigInteger(), existing_nullable=True,
                    existing_server_default=False)

    op.create_foreign_key(
        constraint_name=None, source_table=TABLE_NAME,
        referent_table='standardattributes',
        local_cols=['standard_attr_id'], remote_cols=['id'],
        ondelete='CASCADE')
    op.create_unique_constraint(
        constraint_name='uniq_%s0standard_attr_id' % TABLE_NAME,
        table_name=TABLE_NAME, columns=['standard_attr_id'])
