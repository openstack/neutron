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

"""nsx_router_mappings

Revision ID: 4ca36cfc898c
Revises: 3d3cb89d84ee
Create Date: 2014-01-08 10:41:43.373031

"""

# revision identifiers, used by Alembic.
revision = '4ca36cfc898c'
down_revision = '3d3cb89d84ee'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():

    if not migration.schema_has_table('routers'):
        # In the database we are migrating from, the configured plugin
        # did not create the routers table.
        return

    # Create table for router/lrouter mappings
    op.create_table(
        'neutron_nsx_router_mappings',
        sa.Column('neutron_id', sa.String(length=36), nullable=False),
        sa.Column('nsx_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['neutron_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('neutron_id'),
    )
    # Execute statement to a record in nsx_router_mappings for
    # each record in routers
    op.execute("INSERT INTO neutron_nsx_router_mappings SELECT id,id "
               "from routers")
