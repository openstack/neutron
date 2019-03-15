# Copyright 2016 Intel Corporation.
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
from neutron_lib import constants
import sqlalchemy as sa

"""add_qos_minimum_bandwidth_rules

Revision ID: 0f5bef0f87d4
Revises: a5648cfeeadf
Create Date: 2016-07-29 14:33:37.243487

"""

# revision identifiers, used by Alembic.
revision = '0f5bef0f87d4'
down_revision = 'a5648cfeeadf'


def upgrade():
    op.create_table(
        'qos_minimum_bandwidth_rules',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('qos_policy_id',
                  sa.String(length=36),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False, index=True),
        sa.Column('min_kbps', sa.Integer()),
        sa.Column('direction', sa.Enum(constants.EGRESS_DIRECTION,
                                       constants.INGRESS_DIRECTION,
                                       name='directions'),
                  nullable=False, server_default=constants.EGRESS_DIRECTION),
        sa.UniqueConstraint(
            'qos_policy_id', 'direction',
            name='qos_minimum_bandwidth_rules0qos_policy_id0direction')
    )
