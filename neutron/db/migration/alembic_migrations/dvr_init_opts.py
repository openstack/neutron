# Copyright 2015 OpenStack Foundation
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

# Initial operations for dvr

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'dvr_host_macs',
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('mac_address', sa.String(length=32),
                  nullable=False, unique=True),
        sa.PrimaryKeyConstraint('host')
    )
    op.create_table(
        'ml2_dvr_port_bindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.Column('vif_type', sa.String(length=64), nullable=False),
        sa.Column('vif_details', sa.String(length=4095),
                  nullable=False, server_default=''),
        sa.Column('vnic_type', sa.String(length=64),
                  nullable=False, server_default='normal'),
        sa.Column('profile', sa.String(length=4095),
                  nullable=False, server_default=''),
        sa.Column(u'status', sa.String(16), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id', 'host')
    )
    op.create_table(
        'csnat_l3_agent_bindings',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('l3_agent_id', sa.String(length=36), nullable=False),
        sa.Column('host_id', sa.String(length=255), nullable=True),
        sa.Column('csnat_gw_port_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['l3_agent_id'], ['agents.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['csnat_gw_port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id', 'l3_agent_id')
    )
