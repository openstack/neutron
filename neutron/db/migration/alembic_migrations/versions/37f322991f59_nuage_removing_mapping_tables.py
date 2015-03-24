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

"""removing_mapping_tables

Revision ID: 37f322991f59
Revises: 2026156eab2f
Create Date: 2014-07-09 17:25:29.242948

"""

# revision identifiers, used by Alembic.
revision = '37f322991f59'
down_revision = '2026156eab2f'

from alembic import op


def upgrade():
    op.drop_table('nuage_floatingip_mapping')
    op.drop_table('nuage_floatingip_pool_mapping')
    op.drop_table('nuage_routerroutes_mapping')
    op.drop_table('nuage_port_mapping')
    op.drop_table('nuage_router_zone_mapping')
