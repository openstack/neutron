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

"""network_rbac_external

Revision ID: 5ffceebfada
Revises: c6c112992c9
Create Date: 2015-06-14 13:12:04.012457

"""

# revision identifiers, used by Alembic.
revision = '5ffceebfada'
down_revision = 'c6c112992c9'
depends_on = ()

from alembic import op
from oslo_utils import uuidutils
import sqlalchemy as sa


# A simple model of the external network table with only the fields needed for
# the migration.
external = sa.Table('externalnetworks', sa.MetaData(),
                    sa.Column('network_id', sa.String(length=36),
                              nullable=False))

network = sa.Table('networks', sa.MetaData(),
                   sa.Column('id', sa.String(length=36), nullable=False),
                   sa.Column('tenant_id', sa.String(length=255)))

networkrbacs = sa.Table(
    'networkrbacs', sa.MetaData(),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('object_id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=True,
              index=True),
    sa.Column('target_tenant', sa.String(length=255),
              nullable=False),
    sa.Column('action', sa.String(length=255), nullable=False))


def upgrade():
    op.bulk_insert(networkrbacs, get_values())


def get_values():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    net_to_tenant_id = {}
    for row in session.query(network).all():
        net_to_tenant_id[row[0]] = row[1]
    for row in session.query(external).all():
        values.append({'id': uuidutils.generate_uuid(), 'object_id': row[0],
                       'tenant_id': net_to_tenant_id[row[0]],
                       'target_tenant': '*', 'action': 'access_as_external'})
    # this commit appears to be necessary to allow further operations
    session.commit()
    return values
