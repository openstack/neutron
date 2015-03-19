# Copyright 2014 OpenStack Foundation
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

# Initial operations for NEC plugin


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'ofcportmappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id'))

    op.create_table(
        'ofcroutermappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id'))

    op.create_table(
        'routerproviders',
        sa.Column('provider', sa.String(length=255), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'))

    op.create_table(
        'ofcnetworks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ofctenantmappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id'))

    op.create_table(
        'ofcfiltermappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id'))

    op.create_table(
        'ofcnetworkmappings',
        sa.Column('ofc_id', sa.String(length=255), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('quantum_id'),
        sa.UniqueConstraint('ofc_id'))

    op.create_table(
        'ofcfilters',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ofcports',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ofctenants',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'packetfilters',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=16), nullable=False),
        sa.Column('in_port', sa.String(length=36), nullable=True),
        sa.Column('src_mac', sa.String(length=32), nullable=False),
        sa.Column('dst_mac', sa.String(length=32), nullable=False),
        sa.Column('eth_type', sa.Integer(), nullable=False),
        sa.Column('src_cidr', sa.String(length=64), nullable=False),
        sa.Column('dst_cidr', sa.String(length=64), nullable=False),
        sa.Column('protocol', sa.String(length=16), nullable=False),
        sa.Column('src_port', sa.Integer(), nullable=False),
        sa.Column('dst_port', sa.Integer(), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['in_port'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'portinfos',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('datapath_id', sa.String(length=36), nullable=False),
        sa.Column('port_no', sa.Integer(), nullable=False),
        sa.Column('vlan_id', sa.Integer(), nullable=False),
        sa.Column('mac', sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(['id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))
