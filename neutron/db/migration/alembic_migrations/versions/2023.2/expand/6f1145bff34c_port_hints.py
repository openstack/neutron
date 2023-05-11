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
from neutron_lib.db import constants as db_const
import sqlalchemy as sa


"""port_hints

Revision ID: 6f1145bff34c
Revises: 93f394357a27
Create Date: 2023-01-01 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = '6f1145bff34c'
down_revision = '93f394357a27'


def upgrade():
    op.create_table(
        'porthints',
        sa.Column(
            'port_id',
            sa.String(length=db_const.UUID_FIELD_SIZE),
            sa.ForeignKey('ports.id', ondelete='CASCADE'),
            primary_key=True),
        sa.Column('hints',
            sa.String(4095),
            nullable=False),
    )
