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

# Initial operations for security group extension
from alembic import op
import sqlalchemy as sa


rule_direction_enum = sa.Enum('ingress', 'egress',
                              name='securitygrouprules_direction')


def upgrade():
    op.create_table(
        'securitygroups',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'securitygrouprules',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('security_group_id', sa.String(length=36), nullable=False),
        sa.Column('remote_group_id', sa.String(length=36), nullable=True),
        sa.Column('direction', rule_direction_enum, nullable=True),
        sa.Column('ethertype', sa.String(length=40), nullable=True),
        sa.Column('protocol', sa.String(length=40), nullable=True),
        sa.Column('port_range_min', sa.Integer(), nullable=True),
        sa.Column('port_range_max', sa.Integer(), nullable=True),
        sa.Column('remote_ip_prefix', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['security_group_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['remote_group_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'securitygroupportbindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('security_group_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['security_group_id'], ['securitygroups.id']),
        sa.PrimaryKeyConstraint('port_id', 'security_group_id'))
