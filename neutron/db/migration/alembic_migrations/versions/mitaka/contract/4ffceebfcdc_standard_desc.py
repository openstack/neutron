# Copyright 2015 OpenStack Foundation
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

"""standard_desc

Revision ID: 4ffceebfcdc
Revises: 5ffceebfada
Create Date: 2016-02-10 23:12:04.012457

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '4ffceebfcdc'
down_revision = '5ffceebfada'
depends_on = ('0e66c5227a8a',)

neutron_milestone = [migration.MITAKA]


# A simple model of the security groups table with only the fields needed for
# the migration.
securitygroups = sa.Table('securitygroups', sa.MetaData(),
                          sa.Column('standard_attr_id', sa.BigInteger(),
                                    nullable=False),
                          sa.Column('description', sa.String(length=255)))

standardattr = sa.Table(
    'standardattributes', sa.MetaData(),
    sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
    sa.Column('description', sa.String(length=255)))


def upgrade():
    migrate_values()
    op.drop_column('securitygroups', 'description')


def migrate_values():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    for row in session.query(securitygroups):
        values.append({'id': row[0],
                       'description': row[1]})
    with session.begin(subtransactions=True):
        for value in values:
            session.execute(
                standardattr.update().values(
                    description=value['description']).where(
                        standardattr.c.id == value['id']))
    # this commit appears to be necessary to allow further operations
    session.commit()
