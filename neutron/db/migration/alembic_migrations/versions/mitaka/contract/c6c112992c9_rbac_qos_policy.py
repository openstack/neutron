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

"""rbac_qos_policy

Revision ID: c6c112992c9
Revises: 8a6d8bdae39
Create Date: 2015-11-25 18:45:03.831359

"""

from alembic import op
from oslo_utils import uuidutils
import sqlalchemy as sa

from neutron.db import rbac_db_models

# revision identifiers, used by Alembic.

revision = 'c6c112992c9'
down_revision = 'e3278ee65050'
depends_on = ('15e43b934f81',)

qos_rbacs = sa.Table(
    'qospolicyrbacs', sa.MetaData(),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=255),
              nullable=True),
    sa.Column('target_tenant', sa.String(length=255),
              nullable=False),
    sa.Column('action', sa.String(length=255), nullable=False),
    sa.Column('object_id', sa.String(length=36), nullable=False))

# A simple model of the qos_policies table with only the fields needed for
# the migration.
qos_policy = sa.Table('qos_policies', sa.MetaData(),
                      sa.Column('id', sa.String(length=36), nullable=False),
                      sa.Column('tenant_id',
                                sa.String(length=255)),
                      sa.Column('shared', sa.Boolean(), nullable=False))


def upgrade():
    op.bulk_insert(qos_rbacs, get_values())
    op.drop_column('qos_policies', 'shared')


def get_values():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    for row in session.query(qos_policy).filter(qos_policy.c.shared).all():
        values.append({'id': uuidutils.generate_uuid(), 'object_id': row[0],
                       'tenant_id': row[1], 'target_tenant': '*',
                       'action': rbac_db_models.ACCESS_SHARED})
    session.commit()
    return values
