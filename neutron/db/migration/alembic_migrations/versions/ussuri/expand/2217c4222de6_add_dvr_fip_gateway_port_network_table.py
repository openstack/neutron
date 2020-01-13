# Copyright 2020 OpenStack Foundation
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


"""add dvr FIP gateway port network table

Revision ID: 2217c4222de6
Revises: Ibac91d24da2
Create Date: 2020-01-13 01:47:11.649472

"""

# revision identifiers, used by Alembic.
revision = '2217c4222de6'
down_revision = 'Ibac91d24da2'


def upgrade():
    op.create_table(
        'dvr_fip_gateway_port_network',
        sa.Column('network_id', sa.String(length=36),
                  sa.ForeignKey('networks.id', ondelete='CASCADE'),
                  primary_key=True),
        sa.Column('agent_id', sa.String(length=36),
                  sa.ForeignKey('agents.id', ondelete='CASCADE'),
                  primary_key=True)
    )
