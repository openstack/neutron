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

"""Drop embrane plugin table

Revision ID: 1b294093239c
Revises: 4af11ca47297
Create Date: 2015-10-09 14:07:59.968597

"""

# revision identifiers, used by Alembic.
revision = '1b294093239c'
down_revision = '4af11ca47297'

from alembic import op


def upgrade():
    op.drop_table('embrane_pool_port')
