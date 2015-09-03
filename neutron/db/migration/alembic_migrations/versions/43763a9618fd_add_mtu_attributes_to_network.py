# Copyright 2015 OpenStack Foundation
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

"""add mtu attributes to network

Revision ID: 43763a9618fd
Revises: 16cdf118d31d
Create Date: 2015-02-05 17:44:14.161377

"""

# revision identifiers, used by Alembic.
revision = '43763a9618fd'
down_revision = '16cdf118d31d'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('networks', sa.Column('mtu', sa.Integer(),
                  nullable=True))
