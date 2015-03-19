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

"""ext_l3_ha_mode

Revision ID: 16a27a58e093
Revises: 86d6d9776e2b
Create Date: 2014-02-01 10:24:12.412733

"""

# revision identifiers, used by Alembic.
revision = '16a27a58e093'
down_revision = '86d6d9776e2b'


from alembic import op
import sqlalchemy as sa

l3_ha_states = sa.Enum('active', 'standby', name='l3_ha_states')


def upgrade(active_plugins=None, options=None):
    op.add_column('router_extra_attributes',
                  sa.Column('ha', sa.Boolean(),
                            nullable=False,
                            server_default=sa.sql.false()))
    op.add_column('router_extra_attributes',
                  sa.Column('ha_vr_id', sa.Integer()))

    op.create_table('ha_router_agent_port_bindings',
                    sa.Column('port_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('router_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('l3_agent_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('state', l3_ha_states,
                              server_default='standby'),
                    sa.PrimaryKeyConstraint('port_id'),
                    sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['l3_agent_id'], ['agents.id'],
                                            ondelete='CASCADE'))

    op.create_table('ha_router_networks',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=False, primary_key=True),
                    sa.Column('network_id', sa.String(length=36),
                              nullable=False,
                              primary_key=True),
                    sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                            ondelete='CASCADE'))

    op.create_table('ha_router_vrid_allocations',
                    sa.Column('network_id', sa.String(length=36),
                              nullable=False,
                              primary_key=True),
                    sa.Column('vr_id', sa.Integer(),
                              nullable=False,
                              primary_key=True),
                    sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                            ondelete='CASCADE'))
