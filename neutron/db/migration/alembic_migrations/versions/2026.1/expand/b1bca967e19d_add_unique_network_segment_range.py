# Copyright 2025 OpenStack Foundation
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

"""Add unique constraint to the network segment range

Revision ID: b1bca967e19d
Revises: ad80a9f07c5c
Create Date: 2025-04-08 11:28:47.791807

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b1bca967e19d'
down_revision = 'd553edeb540f'

network_segment_range_network_type = sa.Enum(
    'vlan', 'vxlan', 'gre', 'geneve',
    name='network_segment_range_network_type')

TABLE_NAME = 'network_segment_ranges'
network_segment_range_table = sa.Table(
    TABLE_NAME, sa.MetaData(),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('default', sa.Boolean(), nullable=False),
    sa.Column('shared', sa.Boolean(), nullable=False),
    sa.Column('project_id', sa.String(length=255), nullable=True),
    sa.Column('network_type', network_segment_range_network_type,
              nullable=False),
    sa.Column('physical_network', sa.String(length=64), nullable=False,
              server_default=''),
    sa.Column('minimum', sa.Integer(), nullable=True),
    sa.Column('maximum', sa.Integer(), nullable=True),
    sa.Column('standard_attr_id', sa.BigInteger(), nullable=False),
)


def upgrade():
    unique_name = 'uniq_network_segment_ranges'
    unique_columns = ['default',
                      'network_type',
                      'physical_network',
                      'minimum',
                      'maximum',
                      ]

    inspect = sa.engine.reflection.Inspector.from_engine(op.get_bind())
    unique_constraints = inspect.get_unique_constraints(TABLE_NAME)
    for unique_constraint in unique_constraints:
        if unique_constraint['name'] == unique_name:
            # The unique constraint already exists.
            return

    migrate_values()
    clear_duplicate_values()
    op.alter_column(TABLE_NAME, 'physical_network', nullable=False,
                    server_default='', existing_type=sa.String(64))
    op.create_unique_constraint(
        columns=unique_columns,
        constraint_name=unique_name,
        table_name=TABLE_NAME)


def clear_duplicate_values():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    for row in session.query(network_segment_range_table):
        id = row[0]
        item = {'default': row[2],
                'network_type': row[5],
                'physical_network': row[6],
                'minimum': row[7],
                'maximum': row[8]}
        if item not in values:
            values.append(item)
        else:
            session.execute(
                network_segment_range_table.delete().where(
                    network_segment_range_table.c.id == id))
    session.commit()


def migrate_values():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    for row in session.query(network_segment_range_table):
        values.append({'id': row[0],
                       'physical_network': row[6]})
    for value in values:
        physical_network = value['physical_network'] or ''
        session.execute(
             network_segment_range_table.update().values(
                 physical_network=physical_network
             ).where(network_segment_range_table.c.id == value['id']))
    session.commit()
