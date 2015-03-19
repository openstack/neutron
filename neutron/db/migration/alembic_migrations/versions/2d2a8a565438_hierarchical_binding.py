# Copyright 2015 OpenStack Foundation
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

"""ML2 hierarchical binding

Revision ID: 2d2a8a565438
Revises: 4119216b7365
Create Date: 2014-08-24 21:56:36.422885

"""

# revision identifiers, used by Alembic.
revision = '2d2a8a565438'
down_revision = '4119216b7365'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection

port_binding_tables = ['ml2_port_bindings', 'ml2_dvr_port_bindings']


def upgrade():

    inspector = reflection.Inspector.from_engine(op.get_bind())
    fk_name = [fk['name'] for fk in
               inspector.get_foreign_keys('ml2_port_bindings')
               if 'segment' in fk['constrained_columns']]
    fk_name_dvr = [fk['name'] for fk in
                   inspector.get_foreign_keys('ml2_dvr_port_bindings')
                   if 'segment' in fk['constrained_columns']]

    op.create_table(
        'ml2_port_binding_levels',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('level', sa.Integer(), autoincrement=False, nullable=False),
        sa.Column('driver', sa.String(length=64), nullable=True),
        sa.Column('segment_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['segment_id'], ['ml2_network_segments.id'],
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('port_id', 'host', 'level')
    )

    for table in port_binding_tables:
        op.execute((
            "INSERT INTO ml2_port_binding_levels "
            "SELECT port_id, host, 0 AS level, driver, segment AS segment_id "
            "FROM %s "
            "WHERE host <> '' "
            "AND driver <> '';"
        ) % table)

    op.drop_constraint(fk_name_dvr[0], 'ml2_dvr_port_bindings', 'foreignkey')
    op.drop_column('ml2_dvr_port_bindings', 'cap_port_filter')
    op.drop_column('ml2_dvr_port_bindings', 'segment')
    op.drop_column('ml2_dvr_port_bindings', 'driver')

    op.drop_constraint(fk_name[0], 'ml2_port_bindings', 'foreignkey')
    op.drop_column('ml2_port_bindings', 'driver')
    op.drop_column('ml2_port_bindings', 'segment')
