# Copyright 2017 OpenStack Foundation
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

"""Add data_plane_status to Port

Revision ID: 804a3c76314c
Revises: a9c43481023c
Create Date: 2017-01-17 13:51:45.737987

"""

# revision identifiers, used by Alembic.
revision = '804a3c76314c'
down_revision = 'a9c43481023c'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('portdataplanestatuses',
                    sa.Column('port_id', sa.String(36),
                              sa.ForeignKey('ports.id',
                                            ondelete="CASCADE"),
                              primary_key=True, index=True),
                    sa.Column('data_plane_status', sa.String(length=16),
                              nullable=True))
