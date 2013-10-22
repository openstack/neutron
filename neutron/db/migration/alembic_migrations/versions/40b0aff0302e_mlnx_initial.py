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

"""mlnx_initial

Revision ID: 40b0aff0302e
Revises: 49f5e553f61f
Create Date: 2014-01-12 14:51:49.273105

"""

# revision identifiers, used by Alembic.
revision = '40b0aff0302e'
down_revision = '49f5e553f61f'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.mlnx.mlnx_plugin.MellanoxEswitchPlugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

securitygrouprules_direction = sa.Enum('ingress', 'egress',
                                       name='securitygrouprules_direction')


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'securitygroups',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'segmentation_id_allocation',
        sa.Column('physical_network', sa.String(length=64), nullable=False),
        sa.Column('segmentation_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('allocated', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'segmentation_id'),
    )

    op.create_table(
        'quotas',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(255), index=True),
        sa.Column('resource', sa.String(255)),
        sa.Column('limit', sa.Integer()),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'mlnx_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'),
    )

    op.create_table(
        'networkdhcpagentbindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('dhcp_agent_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['dhcp_agent_id'], ['agents.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'dhcp_agent_id'),
    )

    op.create_table(
        'securitygrouprules',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('security_group_id', sa.String(length=36), nullable=False),
        sa.Column('remote_group_id', sa.String(length=36), nullable=True),
        sa.Column('direction', securitygrouprules_direction,
                  nullable=True),
        sa.Column('ethertype', sa.String(length=40), nullable=True),
        sa.Column('protocol', sa.String(length=40), nullable=True),
        sa.Column('port_range_min', sa.Integer(), nullable=True),
        sa.Column('port_range_max', sa.Integer(), nullable=True),
        sa.Column('remote_ip_prefix', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['remote_group_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['security_group_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'port_profile',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('vnic_type', sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
    )

    op.add_column('routers', sa.Column('enable_snat', sa.Boolean(),
                                       nullable=False, server_default="1"))
    op.create_table(
        'securitygroupportbindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('security_group_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['security_group_id'], ['securitygroups.id'],),
        sa.PrimaryKeyConstraint('port_id', 'security_group_id'),
    )

    op.create_table(
        'portbindingports',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
    )

    op.rename_table(
        'routes',
        'subnetroutes',
    )

    op.create_table(
        'routerl3agentbindings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.Column('l3_agent_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['l3_agent_id'], ['agents.id'],
                                ondelete='CASCADE'),

        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'routerroutes',
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.Column('nexthop', sa.String(length=64), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('destination', 'nexthop', 'router_id'),
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.rename_table(
        'subnetroutes',
        'routes',
    )

    op.drop_table('routerroutes')
    op.drop_table('routerl3agentbindings')
    op.drop_table('portbindingports')
    op.drop_table('securitygroupportbindings')
    op.drop_column('routers', 'enable_snat')
    op.drop_table('port_profile')
    op.drop_table('securitygrouprules')
    securitygrouprules_direction.drop(op.get_bind(), checkfirst=False)
    op.drop_table('networkdhcpagentbindings')
    op.drop_table('mlnx_network_bindings')
    op.drop_table('quotas')
    op.drop_table('segmentation_id_allocation')
    op.drop_table('securitygroups')
