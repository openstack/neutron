# Copyright (c) 2021 Ericsson Software Technology
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
from neutron_lib import constants as n_const
from neutron_lib.db import constants as db_const
import sqlalchemy as sa


"""qos_minimum_packet_rate_rules

Revision ID: c181bb1d89e4
Revises: 1bb3393de75d
Create Date: 2021-07-09 15:47:46.826903

"""

# revision identifiers, used by Alembic.
revision = 'c181bb1d89e4'
down_revision = '1bb3393de75d'


def upgrade():
    op.create_table(
        'qos_minimum_packet_rate_rules',
        sa.Column('id', sa.String(db_const.UUID_FIELD_SIZE),
                  primary_key=True),
        sa.Column('qos_policy_id', sa.String(db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  index=True),
        sa.Column('min_kpps', sa.Integer(), nullable=False),
        sa.Column('direction',
                  sa.Enum(*n_const.VALID_DIRECTIONS_AND_ANY,
                          name="qos_minimum_packet_rate_rules_directions"),
                  nullable=False,
                  server_default=n_const.EGRESS_DIRECTION),
        sa.UniqueConstraint('qos_policy_id', 'direction',
            name='qos_minimum_packet_rate_rules0qos_policy_id0direction')
    )
