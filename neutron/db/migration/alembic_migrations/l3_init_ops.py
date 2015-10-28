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

# Initial operations for l3 extension

from alembic import op
import sqlalchemy as sa

l3_ha_states = sa.Enum('active', 'standby', name='l3_ha_states')


def create_routerroutes():
    op.create_table(
        'routerroutes',
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.Column('nexthop', sa.String(length=64), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('destination', 'nexthop', 'router_id'))


def upgrade():
    op.create_table(
        'externalnetworks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))

    op.create_table(
        'routers',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=True),
        sa.Column('gw_port_id', sa.String(length=36), nullable=True),
        sa.Column('enable_snat', sa.Boolean(), nullable=False,
                  server_default=sa.sql.true()),
        sa.ForeignKeyConstraint(['gw_port_id'], ['ports.id'], ),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'floatingips',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('floating_ip_address', sa.String(length=64), nullable=False),
        sa.Column('floating_network_id', sa.String(length=36), nullable=False),
        sa.Column('floating_port_id', sa.String(length=36), nullable=False),
        sa.Column('fixed_port_id', sa.String(length=36), nullable=True),
        sa.Column('fixed_ip_address', sa.String(length=64), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.Column('last_known_router_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.ForeignKeyConstraint(['fixed_port_id'], ['ports.id'], ),
        sa.ForeignKeyConstraint(['floating_port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'], ),
        sa.PrimaryKeyConstraint('id'))

    create_routerroutes()

    op.create_table(
        'routerl3agentbindings',
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.Column('l3_agent_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['l3_agent_id'], ['agents.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id', 'l3_agent_id'))
    op.create_table(
        'router_extra_attributes',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('distributed', sa.Boolean(), nullable=False,
                  server_default=sa.sql.false()),
        sa.Column('service_router', sa.Boolean(), nullable=False,
                  server_default=sa.sql.false()),
        sa.Column('ha', sa.Boolean(), nullable=False,
                  server_default=sa.sql.false()),
        sa.Column('ha_vr_id', sa.Integer()),
        sa.ForeignKeyConstraint(
            ['router_id'], ['routers.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id')
    )
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
    op.create_table(
        'routerports',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('port_type', sa.String(length=255)),
        sa.PrimaryKeyConstraint('router_id', 'port_id'),
        sa.ForeignKeyConstraint(
            ['router_id'],
            ['routers.id'],
            ondelete='CASCADE'
        ),
        sa.ForeignKeyConstraint(
            ['port_id'],
            ['ports.id'],
            ondelete='CASCADE'
        ),
    )
