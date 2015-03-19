# Copyright (c) 2014 Thales Services SAS
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

"""correct Vxlan Endpoint primary key

Revision ID: 4eba2f05c2f4
Revises: 884573acbf1c
Create Date: 2014-07-07 22:48:38.544323

"""

# revision identifiers, used by Alembic.
revision = '4eba2f05c2f4'
down_revision = '884573acbf1c'


from alembic import op


TABLE_NAME = 'ml2_vxlan_endpoints'
PK_NAME = 'ml2_vxlan_endpoints_pkey'


def upgrade():
    op.drop_constraint(PK_NAME, TABLE_NAME, type_='primary')
    op.create_primary_key(PK_NAME, TABLE_NAME, cols=['ip_address'])
