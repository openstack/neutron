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

"""port forwarding

Revision ID: 867d39095bf4
Revises: 61663558142c
Create Date: 2018-01-15 01:52:31.308888

"""

from alembic import op
import sqlalchemy as sa

from neutron_lib.db import constants

# revision identifiers, used by Alembic.
revision = '867d39095bf4'
down_revision = '61663558142c'


def upgrade():
    op.create_table(
        'portforwardings',
        sa.Column('id', sa.String(length=constants.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('floatingip_id',
                  sa.String(length=constants.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('external_port', sa.Integer(), nullable=False),
        sa.Column('internal_neutron_port_id',
                  sa.String(length=constants.UUID_FIELD_SIZE),
                  nullable=False),
        sa.Column('protocol', sa.String(length=40), nullable=False),
        sa.Column('socket', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['floatingip_id'], ['floatingips.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['internal_neutron_port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('floatingip_id', 'external_port',
                            name='uniq_port_forwardings0floatingip_id0'
                                 'external_port'),
        sa.UniqueConstraint('internal_neutron_port_id', 'socket',
                            name='uniq_port_forwardings0'
                                 'internal_neutron_port_id0socket')
    )
