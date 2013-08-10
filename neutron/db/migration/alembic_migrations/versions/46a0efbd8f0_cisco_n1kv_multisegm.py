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

"""cisco_n1kv_multisegment_trunk

Revision ID: 46a0efbd8f0
Revises: 53bbd27ec841
Create Date: 2013-08-20 20:44:08.711110

"""

revision = '46a0efbd8f0'
down_revision = '53bbd27ec841'

migration_for_plugins = [
    'neutron.plugins.cisco.network_plugin.PluginV2'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'cisco_n1kv_trunk_segments',
        sa.Column('trunk_segment_id', sa.String(length=36), nullable=False),
        sa.Column('segment_id', sa.String(length=36), nullable=False),
        sa.Column('dot1qtag', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['trunk_segment_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('trunk_segment_id', 'segment_id', 'dot1qtag')
    )
    op.create_table(
        'cisco_n1kv_multi_segments',
        sa.Column('multi_segment_id', sa.String(length=36), nullable=False),
        sa.Column('segment1_id', sa.String(length=36), nullable=False),
        sa.Column('segment2_id', sa.String(length=36), nullable=False),
        sa.Column('encap_profile_name', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['multi_segment_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('multi_segment_id', 'segment1_id',
                                'segment2_id')
    )
    op.alter_column('cisco_network_profiles', 'segment_type',
                    existing_type=sa.Enum('vlan', 'vxlan', 'trunk',
                                          'multi-segment'),
                    existing_nullable=False)
    op.add_column('cisco_network_profiles',
                  sa.Column('sub_type', sa.String(length=255), nullable=True))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('cisco_n1kv_trunk_segments')
    op.drop_table('cisco_n1kv_multi_segments')
    op.alter_column('cisco_network_profiles', 'segment_type',
                    existing_type=sa.Enum('vlan', 'vxlan'),
                    existing_nullable=False)
    op.drop_column('cisco_network_profiles', 'sub_type')
