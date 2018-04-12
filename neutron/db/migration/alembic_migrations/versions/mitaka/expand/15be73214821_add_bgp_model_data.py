# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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

"""add dynamic routing model data

Revision ID: 15be73214821
Create Date: 2015-07-29 13:16:08.604175

"""

# revision identifiers, used by Alembic.
revision = '15be73214821'
down_revision = '19f26505c74f'


def upgrade():

    op.create_table(
        'bgp_speakers',
        sa.Column('id', sa.String(length=36),
                  nullable=False),
        sa.Column('name', sa.String(length=255),
                  nullable=False),
        sa.Column('local_as', sa.Integer, nullable=False,
                  autoincrement=False),
        sa.Column('ip_version', sa.Integer, nullable=False,
                  autoincrement=False),
        sa.Column('tenant_id',
                  sa.String(length=255),
                  nullable=True,
                  index=True),
        sa.Column('advertise_floating_ip_host_routes', sa.Boolean(),
                  nullable=False),
        sa.Column('advertise_tenant_networks', sa.Boolean(),
                  nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'bgp_peers',
        sa.Column('id', sa.String(length=36),
                  nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('auth_type', sa.String(length=16), nullable=False),
        sa.Column('password', sa.String(length=255), nullable=True),
        sa.Column('peer_ip',
                  sa.String(length=64),
                  nullable=False),
        sa.Column('remote_as', sa.Integer, nullable=False,
                  autoincrement=False),
        sa.Column('tenant_id',
                  sa.String(length=255),
                  nullable=True,
                  index=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'bgp_speaker_network_bindings',
        sa.Column('bgp_speaker_id',
                  sa.String(length=36),
                  nullable=False),
        sa.Column('network_id',
                  sa.String(length=36),
                  nullable=True),
        sa.Column('ip_version', sa.Integer, nullable=False,
                  autoincrement=False),
        sa.ForeignKeyConstraint(['bgp_speaker_id'],
                                ['bgp_speakers.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['network_id'],
                                ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'bgp_speaker_id', 'ip_version')
    )

    op.create_table(
        'bgp_speaker_peer_bindings',
        sa.Column('bgp_speaker_id',
                  sa.String(length=36),
                  nullable=False),
        sa.Column('bgp_peer_id',
                  sa.String(length=36),
                  nullable=False),
        sa.ForeignKeyConstraint(['bgp_speaker_id'], ['bgp_speakers.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['bgp_peer_id'], ['bgp_peers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('bgp_speaker_id', 'bgp_peer_id')
    )
