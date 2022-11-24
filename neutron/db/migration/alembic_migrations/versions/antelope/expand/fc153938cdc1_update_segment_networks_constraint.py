# Copyright 2022 OpenStack Foundation
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

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


"""update segment networks constraint

Revision ID: fc153938cdc1
Revises: 5881373af7f5
Create Date: 2022-11-06 13:04:26.390013

"""

# revision identifiers, used by Alembic.
revision = 'fc153938cdc1'
down_revision = '5881373af7f5'

TABLE_NAME = 'networksegments'


def upgrade():
    inspector = sa.inspect(op.get_bind())

    fk_constraints = inspector.get_foreign_keys(TABLE_NAME)
    for fk in fk_constraints:
        if fk['constrained_columns'] == ['network_id']:
            migration.remove_foreign_keys(TABLE_NAME, [fk])
            op.drop_constraint(
                constraint_name=(
                    'uniq_networksegment0network_id0network_type0'
                    'physical_network'),
                table_name=TABLE_NAME,
                type_='unique')
            migration.create_foreign_keys(TABLE_NAME, [fk])
    op.create_unique_constraint(
        ('uniq_networksegment0network_id0network_type0physnet0sidx'),
        TABLE_NAME,
        ['network_id', 'network_type', 'physical_network', 'segment_index'])


def expand_drop_exceptions():
    """We want to drop the old constraint before to add the new one"""
    return {
        sa.Constraint: [
            'uniq_networksegment0network_id0network_type0physical_network'],
        sa.ForeignKeyConstraint: ['networksegments_ibfk_1',
                                  'ml2_network_segments_network_id_fkey']}
