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

# Initial schema operations for VMware plugins


from alembic import op
import sqlalchemy as sa


net_binding_type = sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                           name='tz_network_bindings_binding_type')
l2gw_segmentation_type = sa.Enum('flat', 'vlan',
                                 name='networkconnections_segmentation_type')
qos_marking = sa.Enum('untrusted', 'trusted', name='qosqueues_qos_marking')


def upgrade():
    op.create_table(
        'tz_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('binding_type', net_binding_type, nullable=False),
        sa.Column('phy_uuid', sa.String(length=36), nullable=True),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False, nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'binding_type',
                                'phy_uuid', 'vlan_id'))

    op.create_table(
        'multi_provider_networks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))

    op.create_table(
        'vcns_router_bindings',
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=16), nullable=True),
        sa.Column('lswitch_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('router_id'))

    op.create_table(
        'networkgateways',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True),
        sa.Column('default', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'networkconnections',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('network_gateway_id', sa.String(length=36), nullable=True),
        sa.Column('network_id', sa.String(length=36), nullable=True),
        sa.Column('segmentation_type', l2gw_segmentation_type, nullable=True),
        sa.Column('segmentation_id', sa.Integer(), nullable=True),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_gateway_id'], ['networkgateways.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
        sa.UniqueConstraint('network_gateway_id', 'segmentation_type',
                            'segmentation_id'))

    op.create_table(
        'qosqueues',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('default', sa.Boolean(), nullable=True,
                  server_default=sa.sql.false()),
        sa.Column('min', sa.Integer(), nullable=False),
        sa.Column('max', sa.Integer(), nullable=True),
        sa.Column('qos_marking', qos_marking, nullable=True),
        sa.Column('dscp', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'networkqueuemappings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('queue_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['queue_id'], ['qosqueues.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))

    op.create_table(
        'portqueuemappings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('queue_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['queue_id'], ['qosqueues.id'], ),
        sa.PrimaryKeyConstraint('port_id', 'queue_id'))

    op.create_table(
        'maclearningstates',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('mac_learning_enabled', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'))

    op.create_table('neutron_nsx_port_mappings',
                    sa.Column('neutron_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nsx_port_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nsx_switch_id', sa.String(length=36),
                              nullable=True),
                    sa.ForeignKeyConstraint(['neutron_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('neutron_id'))

    op.create_table(
        'lsn',
        sa.Column('net_id',
                  sa.String(length=36), nullable=False),
        sa.Column('lsn_id',
                  sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('lsn_id'))

    op.create_table(
        'lsn_port',
        sa.Column('lsn_port_id',
                  sa.String(length=36), nullable=False),
        sa.Column('lsn_id',
                  sa.String(length=36), nullable=False),
        sa.Column('sub_id',
                  sa.String(length=36), nullable=False, unique=True),
        sa.Column('mac_addr',
                  sa.String(length=32), nullable=False, unique=True),
        sa.ForeignKeyConstraint(['lsn_id'], ['lsn.lsn_id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('lsn_port_id'))

    op.create_table(
        'neutron_nsx_network_mappings',
        sa.Column('neutron_id', sa.String(length=36), nullable=False),
        sa.Column('nsx_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['neutron_id'], ['networks.id'],
                                ondelete='CASCADE'),
        # There might be multiple switches for a neutron network
        sa.PrimaryKeyConstraint('neutron_id', 'nsx_id'),
    )

    op.create_table(
        'neutron_nsx_router_mappings',
        sa.Column('neutron_id', sa.String(length=36), nullable=False),
        sa.Column('nsx_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['neutron_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('neutron_id'),
    )

    op.create_table(
        'neutron_nsx_security_group_mappings',
        sa.Column('neutron_id', sa.String(length=36), nullable=False),
        sa.Column('nsx_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['neutron_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('neutron_id', 'nsx_id'))

    op.create_table(
        'networkgatewaydevicereferences',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('network_gateway_id', sa.String(length=36), nullable=True),
        sa.Column('interface_name', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['network_gateway_id'], ['networkgateways.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', 'network_gateway_id', 'interface_name'))

    op.create_table(
        'networkgatewaydevices',
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('nsx_id', sa.String(length=36), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('connector_type', sa.String(length=10), nullable=True),
        sa.Column('connector_ip', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.PrimaryKeyConstraint('id'))
