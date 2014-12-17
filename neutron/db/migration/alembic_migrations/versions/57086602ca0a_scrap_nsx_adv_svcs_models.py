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

"""scrap_nsx_adv_svcs_models

Revision ID: 57086602ca0a
Revises: 28c0ffb8ebbd
Create Date: 2014-12-17 22:33:30.465392

"""

# revision identifiers, used by Alembic.
revision = '57086602ca0a'
down_revision = '28c0ffb8ebbd'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_table('vcns_edge_pool_bindings')
    op.drop_table('vcns_firewall_rule_bindings')
    op.drop_table('vcns_edge_monitor_bindings')
    op.drop_table('vcns_edge_vip_bindings')
    op.drop_table(u'routerservicetypebindings')
    op.drop_table(u'servicerouterbindings')


def downgrade():
    op.create_table(
        'servicerouterbindings',
        sa.Column('resource_id', sa.String(length=36), nullable=False),
        sa.Column('resource_type', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], [u'routers.id'],
                                name='servicerouterbindings_ibfk_1'),
        sa.PrimaryKeyConstraint('resource_id', 'resource_type'))
    op.create_table(
        'routerservicetypebindings',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('service_type_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                name='routerservicetypebindings_ibfk_1'),
        sa.PrimaryKeyConstraint(u'router_id'))
    op.create_table(
        'vcns_edge_vip_bindings',
        sa.Column('vip_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=True),
        sa.Column('vip_vseid', sa.String(length=36), nullable=True),
        sa.Column('app_profileid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['vip_id'], ['vips.id'],
                                name='vcns_edge_vip_bindings_ibfk_1'),
        sa.PrimaryKeyConstraint('vip_id'))
    op.create_table(
        'vcns_edge_monitor_bindings',
        sa.Column('monitor_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('monitor_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['monitor_id'], ['healthmonitors.id'],
                                name='vcns_edge_monitor_bindings_ibfk_1'),
        sa.PrimaryKeyConstraint('monitor_id', 'edge_id'))
    op.create_table(
        'vcns_firewall_rule_bindings',
        sa.Column('rule_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('rule_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['rule_id'], ['firewall_rules.id'],
                                name='vcns_firewall_rule_bindings_ibfk_1'),
        sa.PrimaryKeyConstraint('rule_id', u'edge_id'))
    op.create_table(
        'vcns_edge_pool_bindings',
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('pool_vseid', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'],
                                name='vcns_edge_pool_bindings_ibfk_1'),
        sa.PrimaryKeyConstraint('pool_id', 'edge_id'))
