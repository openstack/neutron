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
                           name='nvp_network_bindings_binding_type')
l2gw_segmentation_type = sa.Enum('flat', 'vlan',
                                 name='networkconnections_segmentation_type')
qos_marking = sa.Enum('untrusted', 'trusted', name='qosqueues_qos_marking')


def upgrade():
    op.create_table(
        'quantum_nvp_port_mapping',
        sa.Column('quantum_id', sa.String(length=36), nullable=False),
        sa.Column('nvp_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['quantum_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('quantum_id'))

    op.create_table(
        'nvp_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('binding_type', net_binding_type, nullable=False),
        sa.Column('phy_uuid', sa.String(length=36), nullable=True),
        sa.Column('vlan_id', sa.Integer(), autoincrement=False, nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'binding_type',
                                'phy_uuid', 'vlan_id'))

    op.create_table(
        'nvp_multi_provider_networks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))

    op.create_table(
        'nsxrouterextattributess',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('distributed', sa.Boolean(), nullable=False),
        sa.Column('service_router', sa.Boolean(), nullable=False,
                  server_default='0'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'))

    op.create_table(
        'vcns_router_bindings',
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=16), nullable=True),
        sa.Column('lswitch_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('router_id'))

    op.create_table(
        'vcns_edge_pool_bindings',
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('pool_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('pool_id', 'edge_id'))

    op.create_table(
        'vcns_edge_monitor_bindings',
        sa.Column('monitor_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('monitor_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['monitor_id'], ['healthmonitors.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('monitor_id', 'edge_id'))

    op.create_table(
        'vcns_firewall_rule_bindings',
        sa.Column('rule_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('rule_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['rule_id'], ['firewall_rules.id'], ),
        sa.PrimaryKeyConstraint('rule_id', 'edge_id'))

    op.create_table(
        'vcns_edge_vip_bindings',
        sa.Column('vip_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=True),
        sa.Column('vip_vseid', sa.String(length=36), nullable=True),
        sa.Column('app_profileid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['vip_id'], ['vips.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('vip_id'))

    op.create_table(
        'networkgateways',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True),
        sa.Column('default', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'networkgatewaydevices',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('network_gateway_id', sa.String(length=36), nullable=True),
        sa.Column('interface_name', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['network_gateway_id'],
                                ['networkgateways.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'networkconnections',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
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
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('default', sa.Boolean(), nullable=True),
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
