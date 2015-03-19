# Copyright 2014 OpenStack Foundation
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

"""add router port relationship

Revision ID: 544673ac99ab
Revises: 1680e1f0c4dc
Create Date: 2014-01-14 11:58:13.754747

"""

# revision identifiers, used by Alembic.
revision = '544673ac99ab'
down_revision = '1680e1f0c4dc'

from alembic import op
import sqlalchemy as sa

SQL_STATEMENT = (
    "insert into routerports "
    "select "
    "p.device_id as router_id, p.id as port_id, p.device_owner as port_type "
    "from ports p join routers r on (p.device_id=r.id) "
    "where "
    "(r.tenant_id=p.tenant_id AND p.device_owner='network:router_interface') "
    "OR (p.tenant_id='' AND p.device_owner='network:router_gateway')"
)


def upgrade():
    op.create_table(
        'routerports',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('port_type', sa.String(length=255)),
        sa.PrimaryKeyConstraint('router_id', 'port_id'),
        sa.ForeignKeyConstraint(
            ['router_id'],
            ['routers.id'],
            ondelete='CASCADE'
        ),
        sa.ForeignKeyConstraint(
            ['port_id'],
            ['ports.id'],
            ondelete='CASCADE'
        ),
    )

    op.execute(SQL_STATEMENT)
