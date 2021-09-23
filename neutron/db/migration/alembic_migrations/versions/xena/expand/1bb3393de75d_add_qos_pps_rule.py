# Copyright (c) 2021 China Unicom Cloud Data Co.,Ltd.
# All Rights Reserved.
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

"""add qos policy rule Packet Rate Limit

Revision ID: 1bb3393de75d
Revises: 8df53b0d2c0e
Create Date: 2021-01-22 17:00:03.085196

"""

from alembic import op
import sqlalchemy as sa

from neutron_lib import constants

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '1bb3393de75d'
down_revision = '8df53b0d2c0e'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.XENA]

direction_enum = sa.Enum(
    constants.EGRESS_DIRECTION, constants.INGRESS_DIRECTION,
    name='qos_packet_rate_limit_rules_directions'
)


def upgrade():
    op.create_table(
        'qos_packet_rate_limit_rules',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('qos_policy_id',
                  sa.String(length=36),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False, index=True),
        sa.Column('max_kpps', sa.Integer()),
        sa.Column('max_burst_kpps', sa.Integer()),
        sa.Column('direction', direction_enum,
                  nullable=False,
                  server_default=constants.EGRESS_DIRECTION),
        sa.UniqueConstraint('qos_policy_id', 'direction',
            name='qos_packet_rate_limit_rules0qos_policy_id0direction')
    )
