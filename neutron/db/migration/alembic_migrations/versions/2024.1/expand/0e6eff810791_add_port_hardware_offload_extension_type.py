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


"""Add port hardware offload extension type

Revision ID: 0e6eff810791
Revises: 054e34dbe6b4
Create Date: 2023-05-09 23:52:40.677006

"""

# revision identifiers, used by Alembic.
revision = '0e6eff810791'
down_revision = '054e34dbe6b4'


def upgrade():
    op.create_table('porthardwareoffloadtype',
                    sa.Column('port_id',
                              sa.String(36),
                              sa.ForeignKey('ports.id',
                                            ondelete="CASCADE"),
                              primary_key=True,
                              index=True),
                    sa.Column('hardware_offload_type',
                              sa.String(255),
                              nullable=True)
                    )
