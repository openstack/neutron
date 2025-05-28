# Copyright 2024 OpenStack Foundation
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

import json

from alembic import op
from oslo_serialization import jsonutils
from oslo_utils import strutils
import sqlalchemy as sa

from neutron.db import migration


# Add port trusted attribute
#
# Revision ID: 5bcb7b31ec7d
# Revises: 175fa80908e1
# Create Date: 2024-08-06 12:44:37.193211

# revision identifiers, used by Alembic.
revision = '5bcb7b31ec7d'
down_revision = '175fa80908e1'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.RELEASE_2024_2]


def upgrade():
    port_trusted_table = migration.create_table_if_not_exists(
        'porttrusted',
        sa.Column('port_id',
                  sa.String(36),
                  sa.ForeignKey('ports.id',
                                ondelete="CASCADE"),
                  primary_key=True),
        sa.Column('trusted',
                  sa.Boolean,
                  nullable=True))

    if port_trusted_table is None:
        # Table was already created before so no need to insert any data
        # to it now
        return

    # A simple model of the ml2_port_bindings table, just to get and update
    # binding:profile fields where needed
    port_binding_table = sa.Table(
        'ml2_port_bindings', sa.MetaData(),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('profile', sa.String(length=4095)))

    session = sa.orm.Session(bind=op.get_bind())
    for row in session.query(port_binding_table).all():
        if len(row[1]) == 0:
            continue
        try:
            profile = jsonutils.loads(row[1])
        except json.JSONDecodeError:
            continue
        trusted = profile.pop('trusted', None)
        if trusted is None:
            continue
        session.execute(port_trusted_table.insert().values(
            port_id=row[0],
            trusted=strutils.bool_from_string(trusted)))
        session.execute(port_binding_table.update().values(
            profile=jsonutils.dumps(profile) if profile else '').where(
                port_binding_table.c.port_id == row[0]))
    session.commit()
