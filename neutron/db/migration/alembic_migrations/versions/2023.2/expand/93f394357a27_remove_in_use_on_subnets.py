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
import sqlalchemy as sa


"""remove in_use from subnet

Revision ID: 93f394357a27
Revises: fc153938cdc1
Create Date: 2023-03-07 14:48:15.763633

"""

# revision identifiers, used by Alembic.
revision = '93f394357a27'
down_revision = 'fc153938cdc1'


def upgrade():
    op.drop_column('subnets', 'in_use')


def expand_drop_exceptions():
    """Support dropping 'in_use' column in table 'subnets'"""

    return {
        sa.Column: ['subnets.in_use']
    }
