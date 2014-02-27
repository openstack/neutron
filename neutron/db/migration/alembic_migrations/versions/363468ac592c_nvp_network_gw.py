# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

"""nvp_network_gw

Revision ID: 363468ac592c
Revises: 1c33fa3cd1a1
Create Date: 2013-02-07 03:19:14.455372

"""

# revision identifiers, used by Alembic.
revision = '363468ac592c'
down_revision = '1c33fa3cd1a1'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.plugins.nicira.NeutronPlugin.NvpPluginV2',
    'neutron.plugins.nicira.NeutronServicePlugin.NvpAdvancedPlugin',
    'neutron.plugins.vmware.plugin.NsxPlugin',
    'neutron.plugins.vmware.plugin.NsxServicePlugin'
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return
    op.create_table('networkgateways',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('name', sa.String(length=255), nullable=True),
                    sa.Column('tenant_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('default', sa.Boolean(), nullable=True),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('networkgatewaydevices',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('network_gateway_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('interface_name', sa.String(length=64),
                              nullable=True),
                    sa.ForeignKeyConstraint(['network_gateway_id'],
                                            ['networkgateways.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'))
    op.create_table('networkconnections',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('network_gateway_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('network_id', sa.String(length=36),
                              nullable=True),
                    sa.Column('segmentation_type',
                              sa.Enum('flat', 'vlan',
                                      name="net_conn_seg_type"),
                              nullable=True),
                    sa.Column('segmentation_id', sa.Integer(),
                              nullable=True),
                    sa.Column('port_id', sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['network_gateway_id'],
                                            ['networkgateways.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('port_id'),
                    sa.UniqueConstraint('network_gateway_id',
                                        'segmentation_type',
                                        'segmentation_id'))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('networkconnections')
    op.drop_table('networkgatewaydevices')
    op.drop_table('networkgateways')
