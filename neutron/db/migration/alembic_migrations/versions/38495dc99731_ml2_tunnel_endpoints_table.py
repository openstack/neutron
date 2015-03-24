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

"""ml2_tunnel_endpoints_table

Revision ID: 38495dc99731
Revises: 57086602ca0a
Create Date: 2014-12-22 00:03:33.643799

"""

# revision identifiers, used by Alembic.
revision = '38495dc99731'
down_revision = '57086602ca0a'

from alembic import op
import sqlalchemy as sa

CONSTRAINT_NAME_GRE = 'unique_ml2_gre_endpoints0host'
CONSTRAINT_NAME_VXLAN = 'unique_ml2_vxlan_endpoints0host'


def upgrade():

    op.add_column('ml2_gre_endpoints',
                  sa.Column('host', sa.String(length=255), nullable=True))
    op.create_unique_constraint(
        name=CONSTRAINT_NAME_GRE,
        source='ml2_gre_endpoints',
        local_cols=['host']
    )

    op.add_column('ml2_vxlan_endpoints',
                  sa.Column('host', sa.String(length=255), nullable=True))
    op.create_unique_constraint(
        name=CONSTRAINT_NAME_VXLAN,
        source='ml2_vxlan_endpoints',
        local_cols=['host']
    )
