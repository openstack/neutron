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

"""remove ryu plugin

Revision ID: 408cfbf6923c
Revises: 1f71e54a85e7
Create Date: 2014-11-10 13:17:12.709642

"""

# revision identifiers, used by Alembic.
revision = '408cfbf6923c'
down_revision = '1f71e54a85e7'

from alembic import op


def upgrade():
    op.drop_table('tunnelkeylasts')
    op.drop_table('tunnelkeys')
