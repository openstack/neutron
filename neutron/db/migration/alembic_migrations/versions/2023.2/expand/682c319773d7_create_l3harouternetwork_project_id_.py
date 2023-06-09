# Copyright 2023 OpenStack Foundation
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

from alembic import op


"""Create L3HARouterNetwork.project_id unique constraint

Revision ID: 682c319773d7
Revises: 6f1145bff34c
Create Date: 2023-04-27 13:45:05.103963

"""

# revision identifiers, used by Alembic.
revision = '682c319773d7'
down_revision = '6f1145bff34c'


TABLE = 'ha_router_networks'
COLUMN = 'project_id'


def upgrade():
    op.create_unique_constraint(
        constraint_name='uniq_%s0%s' % (TABLE, COLUMN),
        table_name=TABLE,
        columns=[COLUMN])
