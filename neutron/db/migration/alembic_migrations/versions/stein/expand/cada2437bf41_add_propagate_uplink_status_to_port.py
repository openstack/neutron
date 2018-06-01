# Copyright 2018 OpenStack Foundation
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


"""add propagate_uplink_status to port

Revision ID: cada2437bf41
Revises: d72db3e25539
Create Date: 2018-11-29 19:25:12.197590

"""

# revision identifiers, used by Alembic.
revision = 'cada2437bf41'
down_revision = 'd72db3e25539'


def upgrade():
    op.create_table('portuplinkstatuspropagation',
                    sa.Column('port_id', sa.String(36),
                              sa.ForeignKey('ports.id',
                                            ondelete="CASCADE"),
                              primary_key=True, index=True),
                    sa.Column('propagate_uplink_status', sa.Boolean(),
                              nullable=False,
                              server_default=sa.sql.false()))
