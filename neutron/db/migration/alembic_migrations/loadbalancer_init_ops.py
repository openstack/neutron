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

# Initial schema operations for the load balancer service plugin


from alembic import op
import sqlalchemy as sa


protocols = sa.Enum('HTTP', 'HTTPS', 'TCP', name='lb_protocols')
session_persistence_type = sa.Enum('SOURCE_IP', 'HTTP_COOKIE', 'APP_COOKIE',
                                   name='sesssionpersistences_type')
lb_methods = sa.Enum('ROUND_ROBIN', 'LEAST_CONNECTIONS', 'SOURCE_IP',
                     name='pools_lb_method')
health_monitor_type = sa.Enum('PING', 'TCP', 'HTTP', 'HTTPS',
                              name='healthmontiors_type')


def upgrade():
    op.create_table(
        'healthmonitors',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('type', health_monitor_type, nullable=False),
        sa.Column('delay', sa.Integer(), nullable=False),
        sa.Column('timeout', sa.Integer(), nullable=False),
        sa.Column('max_retries', sa.Integer(), nullable=False),
        sa.Column('http_method', sa.String(length=16), nullable=True),
        sa.Column('url_path', sa.String(length=255), nullable=True),
        sa.Column('expected_codes', sa.String(length=64), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'vips',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('port_id', sa.String(length=36), nullable=True),
        sa.Column('protocol_port', sa.Integer(), nullable=False),
        sa.Column('protocol', protocols, nullable=False),
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('connection_limit', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('pool_id'))

    op.create_table(
        'pools',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('vip_id', sa.String(length=36), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('protocol', protocols, nullable=False),
        sa.Column('lb_method', lb_methods, nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['vip_id'], ['vips.id'], ),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'sessionpersistences',
        sa.Column('vip_id', sa.String(length=36), nullable=False),
        sa.Column('type', session_persistence_type, nullable=False),
        sa.Column('cookie_name', sa.String(length=1024), nullable=True),
        sa.ForeignKeyConstraint(['vip_id'], ['vips.id'], ),
        sa.PrimaryKeyConstraint('vip_id'))

    op.create_table(
        'poolloadbalanceragentbindings',
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('agent_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('pool_id'))

    op.create_table(
        'members',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('address', sa.String(length=64), nullable=False),
        sa.Column('protocol_port', sa.Integer(), nullable=False),
        sa.Column('weight', sa.Integer(), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('pool_id', 'address', 'protocol_port',
                            name='uniq_member0pool_id0address0port'))

    op.create_table(
        'poolmonitorassociations',
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('status_description', sa.String(length=255), nullable=True),
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('monitor_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'], ),
        sa.ForeignKeyConstraint(['monitor_id'], ['healthmonitors.id'], ),
        sa.PrimaryKeyConstraint('pool_id', 'monitor_id'))

    op.create_table(
        'poolstatisticss',
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('bytes_in', sa.BigInteger(), nullable=False),
        sa.Column('bytes_out', sa.BigInteger(), nullable=False),
        sa.Column('active_connections', sa.BigInteger(), nullable=False),
        sa.Column('total_connections', sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'], ),
        sa.PrimaryKeyConstraint('pool_id'))

    op.create_table(
        'embrane_pool_port',
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'],
                                name='embrane_pool_port_ibfk_1'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                name='embrane_pool_port_ibfk_2'),
        sa.PrimaryKeyConstraint('pool_id'))
