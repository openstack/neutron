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

"""ml2_network_segments models change for multi-segment network.

Revision ID: 1f71e54a85e7
Revises: 44621190bc02
Create Date: 2014-10-15 18:30:51.395295

"""

# revision identifiers, used by Alembic.
revision = '1f71e54a85e7'
down_revision = '44621190bc02'


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('ml2_network_segments',
                  sa.Column('segment_index', sa.Integer(), nullable=False,
                  server_default='0'))
