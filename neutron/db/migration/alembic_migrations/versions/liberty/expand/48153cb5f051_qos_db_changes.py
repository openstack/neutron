# Copyright 2015 Huawei Technologies India Pvt Ltd, Inc
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

"""qos db changes

Revision ID: 48153cb5f051
Revises: 1b4c6e320f79
Create Date: 2015-06-24 17:03:34.965101

"""

# revision identifiers, used by Alembic.
revision = '48153cb5f051'
down_revision = '1b4c6e320f79'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'qos_policies',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=255)),
        sa.Column('description', sa.String(length=255)),
        sa.Column('shared', sa.Boolean(), nullable=False),
        sa.Column('tenant_id', sa.String(length=255),
                  index=True))

    op.create_table(
        'qos_network_policy_bindings',
        sa.Column('policy_id', sa.String(length=36),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('network_id', sa.String(length=36),
                  sa.ForeignKey('networks.id', ondelete='CASCADE'),
                  nullable=False, unique=True))

    op.create_table(
        'qos_port_policy_bindings',
        sa.Column('policy_id', sa.String(length=36),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('port_id', sa.String(length=36),
                  sa.ForeignKey('ports.id', ondelete='CASCADE'),
                  nullable=False, unique=True))

    op.create_table(
        'qos_bandwidth_limit_rules',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('qos_policy_id', sa.String(length=36),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False, unique=True),
        sa.Column('max_kbps', sa.Integer()),
        sa.Column('max_burst_kbps', sa.Integer()))
