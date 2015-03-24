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

# Initial operations for extensions:
# allowedaddresspairs
# extradhcpopts
# portbindings
# quotas
# routedserviceinsertion
# servicetype


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'providerresourceassociations',
        sa.Column('provider_name', sa.String(length=255), nullable=False),
        sa.Column('resource_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('provider_name', 'resource_id'),
        sa.UniqueConstraint('resource_id'))

    op.create_table(
        'quotas',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('resource', sa.String(length=255), nullable=True),
        sa.Column('limit', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'allowedaddresspairs',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('mac_address', sa.String(length=32), nullable=False),
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id', 'mac_address', 'ip_address'))

    op.create_table(
        'portbindingports',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'))

    op.create_table(
        'extradhcpopts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('opt_name', sa.String(length=64), nullable=False),
        sa.Column('opt_value', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('port_id', 'opt_name', name='uidx_portid_optname'))

    op.create_table(
        'routerservicetypebindings',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('service_type_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'))

    op.create_table(
        'servicerouterbindings',
        sa.Column('resource_id', sa.String(length=36), nullable=False),
        sa.Column('resource_type', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'], ),
        sa.PrimaryKeyConstraint('resource_id', 'resource_type'))
