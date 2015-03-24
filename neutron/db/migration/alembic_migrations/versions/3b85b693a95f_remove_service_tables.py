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

"""Drop unused servicedefinitions and servicetypes tables.

These tables are created independently on plugins but only dropped if
LoadBalancer plugin is used. Meaning that if LoadBalancer plugin is not set
then these tables were created and never used.

Revision ID: 3b85b693a95f
Revises: 327ee5fde2c7
Create Date: 2014-07-22 03:30:05.837152

"""

# revision identifiers, used by Alembic.
revision = '3b85b693a95f'
down_revision = '327ee5fde2c7'

from alembic import op

from neutron.db import migration


def upgrade():
    for table in ('servicedefinitions', 'servicetypes'):
        if migration.schema_has_table(table):
            op.drop_table(table)
