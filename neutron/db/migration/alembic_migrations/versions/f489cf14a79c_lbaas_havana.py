# Copyright 2013 OpenStack Foundation
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

"""DB support for load balancing service (havana)

Revision ID: f489cf14a79c
Revises: grizzly
Create Date: 2013-02-04 16:32:32.048731

"""

# revision identifiers, used by Alembic.
revision = 'f489cf14a79c'
down_revision = 'grizzly'

migration_for_plugins = [
    'neutron.services.loadbalancer.plugin.LoadBalancerPlugin',
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

lb_protocols = sa.Enum("HTTP", "HTTPS", "TCP", name="lb_protocols")

sesssionpersistences_type = sa.Enum("SOURCE_IP", "HTTP_COOKIE", "APP_COOKIE",
                                    name="sesssionpersistences_type")
pools_lb_method = sa.Enum("ROUND_ROBIN", "LEAST_CONNECTIONS", "SOURCE_IP",
                          name="pools_lb_method")
healthmonitors_type = sa.Enum("PING", "TCP", "HTTP", "HTTPS",
                              name="healthmontiors_type")


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        u'vips',
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'name', sa.String(255), nullable=True),
        sa.Column(u'description', sa.String(255), nullable=True),
        sa.Column(u'port_id', sa.String(36), nullable=True),
        sa.Column(u'protocol_port', sa.Integer(), nullable=False),
        sa.Column(u'protocol', lb_protocols, nullable=False),
        sa.Column(u'pool_id', sa.String(36), nullable=False),
        sa.Column(u'status', sa.String(16), nullable=False),
        sa.Column(u'admin_state_up', sa.Boolean(), nullable=False),
        sa.Column(u'connection_limit', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ),
        sa.UniqueConstraint('pool_id'),
        sa.PrimaryKeyConstraint(u'id')
    )
    op.create_table(
        u'sessionpersistences',
        sa.Column(u'vip_id', sa.String(36), nullable=False),
        sa.Column(u'type', sesssionpersistences_type, nullable=False),
        sa.Column(u'cookie_name', sa.String(1024), nullable=True),
        sa.ForeignKeyConstraint(['vip_id'], [u'vips.id'], ),
        sa.PrimaryKeyConstraint(u'vip_id')
    )
    op.create_table(
        u'pools',
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'vip_id', sa.String(36), nullable=True),
        sa.Column(u'name', sa.String(255), nullable=True),
        sa.Column(u'description', sa.String(255), nullable=True),
        sa.Column(u'subnet_id', sa.String(36), nullable=False),
        sa.Column(u'protocol', lb_protocols, nullable=False),
        sa.Column(u'lb_method', pools_lb_method, nullable=False),
        sa.Column(u'status', sa.String(16), nullable=False),
        sa.Column(u'admin_state_up', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['vip_id'], [u'vips.id'], ),
        sa.PrimaryKeyConstraint(u'id')
    )
    op.create_table(
        u'healthmonitors',
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'type', healthmonitors_type, nullable=False),
        sa.Column(u'delay', sa.Integer(), nullable=False),
        sa.Column(u'timeout', sa.Integer(), nullable=False),
        sa.Column(u'max_retries', sa.Integer(), nullable=False),
        sa.Column(u'http_method', sa.String(16), nullable=True),
        sa.Column(u'url_path', sa.String(255), nullable=True),
        sa.Column(u'expected_codes', sa.String(64), nullable=True),
        sa.Column(u'status', sa.String(16), nullable=False),
        sa.Column(u'admin_state_up', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint(u'id')
    )
    op.create_table(
        u'poolmonitorassociations',
        sa.Column(u'pool_id', sa.String(36), nullable=False),
        sa.Column(u'monitor_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['monitor_id'], [u'healthmonitors.id'], ),
        sa.ForeignKeyConstraint(['pool_id'], [u'pools.id'], ),
        sa.PrimaryKeyConstraint(u'pool_id', u'monitor_id')
    )
    op.create_table(
        u'members',
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'pool_id', sa.String(36), nullable=False),
        sa.Column(u'address', sa.String(64), nullable=False),
        sa.Column(u'protocol_port', sa.Integer(), nullable=False),
        sa.Column(u'weight', sa.Integer(), nullable=False),
        sa.Column(u'status', sa.String(16), nullable=False),
        sa.Column(u'admin_state_up', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['pool_id'], [u'pools.id'], ),
        sa.PrimaryKeyConstraint(u'id')
    )
    op.create_table(
        u'poolstatisticss',
        sa.Column(u'pool_id', sa.String(36), nullable=False),
        sa.Column(u'bytes_in', sa.Integer(), nullable=False),
        sa.Column(u'bytes_out', sa.Integer(), nullable=False),
        sa.Column(u'active_connections', sa.Integer(), nullable=False),
        sa.Column(u'total_connections', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['pool_id'], [u'pools.id'], ),
        sa.PrimaryKeyConstraint(u'pool_id')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.drop_table(u'poolstatisticss')
    op.drop_table(u'members')
    op.drop_table(u'poolmonitorassociations')
    op.drop_table(u'healthmonitors')
    healthmonitors_type.drop(op.get_bind(), checkfirst=False)
    op.drop_table(u'pools')
    pools_lb_method.drop(op.get_bind(), checkfirst=False)
    op.drop_table(u'sessionpersistences')
    sesssionpersistences_type.drop(op.get_bind(), checkfirst=False)
    op.drop_table(u'vips')
    lb_protocols.drop(op.get_bind(), checkfirst=False)
