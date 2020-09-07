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

from alembic import op
from oslo_utils import uuidutils
import sqlalchemy as sa

"""network_rbac

Revision ID: 4ffceebfada
Revises: 30018084ec99
Create Date: 2015-06-14 13:12:04.012457

"""

# revision identifiers, used by Alembic.
revision = '4ffceebfada'
down_revision = '30018084ec99'
depends_on = ('8675309a5c4f',)


# A simple model of the networks table with only the fields needed for
# the migration.
network = sa.Table('networks', sa.MetaData(),
                   sa.Column('id', sa.String(length=36), nullable=False),
                   sa.Column('tenant_id', sa.String(length=255)),
                   sa.Column('shared', sa.Boolean(), nullable=False))

networkrbacs = sa.Table(
    'networkrbacs', sa.MetaData(),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('object_id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=True,
              index=True),
    sa.Column('target_tenant', sa.String(length=255), nullable=False),
    sa.Column('action', sa.String(length=255), nullable=False))


def upgrade():
    op.bulk_insert(networkrbacs, get_values())
    op.drop_column('networks', 'shared')
    # the shared column on subnets was just an internal representation of the
    # shared status of the network it was related to. This is now handled by
    # other logic so we just drop it.
    op.drop_column('subnets', 'shared')


def get_values():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    for row in session.query(network).filter(network.c.shared).all():
        values.append({'id': uuidutils.generate_uuid(), 'object_id': row[0],
                       'tenant_id': row[1], 'target_tenant': '*',
                       'action': 'access_as_shared'})
    # this commit appears to be necessary to allow further operations
    session.commit()
    return values
