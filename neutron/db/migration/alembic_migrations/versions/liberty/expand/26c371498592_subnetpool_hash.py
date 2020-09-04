# Copyright (c) 2015 Thales Services SAS
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

"""subnetpool hash

Revision ID: 26c371498592
Revises: 45f955889773
Create Date: 2015-06-02 21:18:19.942076

"""

# revision identifiers, used by Alembic.
revision = '26c371498592'
down_revision = '45f955889773'


def upgrade():
    op.add_column(
        'subnetpools',
        sa.Column('hash', sa.String(36), nullable=False, server_default=''))
