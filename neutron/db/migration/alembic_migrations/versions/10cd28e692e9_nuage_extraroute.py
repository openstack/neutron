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

"""nuage_extraroute

Revision ID: 10cd28e692e9
Revises: 1b837a7125a9
Create Date: 2014-05-14 14:47:53.148132

"""

# revision identifiers, used by Alembic.
revision = '10cd28e692e9'
down_revision = '1b837a7125a9'


from alembic import op
import sqlalchemy as sa

from neutron.db import migration
from neutron.db.migration.alembic_migrations import l3_init_ops


def upgrade():

    if not migration.schema_has_table('routers'):
        # In the database we are migrating from, the configured plugin
        # did not create the routers table.
        return

    op.create_table(
        'routerroutes_mapping',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('nuage_route_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
    )
    # This table might already exist as it might have been created
    # if another plugin was configured before the nuage one
    if not migration.schema_has_table('routerroutes'):
        l3_init_ops.create_routerroutes()
