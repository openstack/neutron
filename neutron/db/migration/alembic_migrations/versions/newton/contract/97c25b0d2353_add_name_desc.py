# Copyright 2016 NEC Technologies Limited
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

"""Add Name and Description to the networksegments table """

# revision identifiers, used by Alembic.
revision = '97c25b0d2353'
down_revision = 'b12a3ef66e62'
depends_on = ('89ab9a816d70',)

# As this script depends on another migration which was a contract script,
# therefore the following column addition ( which should have been in an
# expand phase ) is also submitted in the contract phase. For information
# about the expand and contract scripts and how the depends_on works, please
# refer <https://docs.openstack.org/neutron/latest/contributor/
# alembic_migrations.html#expand-and-contract-scripts>

TBL = 'networksegments'

TBL_MODEL = sa.Table(TBL, sa.MetaData(),
                     sa.Column('id', sa.String(length=36), nullable=False),
                     sa.Column('standard_attr_id', sa.BigInteger(),
                               nullable=True))


standardattrs = sa.Table(
    'standardattributes', sa.MetaData(),
    sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
    sa.Column('resource_type', sa.String(length=255), nullable=False))


def update_existing_records():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    with session.begin(subtransactions=True):
        for row in session.query(TBL_MODEL):
            # NOTE from kevinbenton: without this disabled, pylint complains
            # about a missing 'dml' argument.
            # pylint: disable=no-value-for-parameter
            res = session.execute(
                standardattrs.insert().values(resource_type=TBL)
            )
            session.execute(
                TBL_MODEL.update().values(
                    standard_attr_id=res.inserted_primary_key[0]).where(
                        TBL_MODEL.c.id == row[0])
            )
    # this commit is necessary to allow further operations
    session.commit()
    return values


def upgrade():
    op.add_column(TBL, sa.Column('standard_attr_id', sa.BigInteger(),
                                 nullable=True))
    op.add_column(TBL,
                  sa.Column('name', sa.String(255),
                            nullable=True))
    update_existing_records()
    op.alter_column(TBL, 'standard_attr_id', nullable=False,
                    existing_type=sa.BigInteger(), existing_nullable=True,
                    existing_server_default=False)
    # add the constraint now that everything is populated on that table
    op.create_foreign_key(
        constraint_name=None, source_table=TBL,
        referent_table='standardattributes',
        local_cols=['standard_attr_id'], remote_cols=['id'],
        ondelete='CASCADE')
    op.create_unique_constraint(
        constraint_name='uniq_%s0standard_attr_id' % TBL,
        table_name=TBL, columns=['standard_attr_id'])


def contract_creation_exceptions():
    """Return create exceptions.

    These elements depend on the networksegments table which are added
    in the contract branch.
    """
    return {
        sa.Column: ['networksegments.name',
                    'networksegments.standard_attr_id'],
    }
