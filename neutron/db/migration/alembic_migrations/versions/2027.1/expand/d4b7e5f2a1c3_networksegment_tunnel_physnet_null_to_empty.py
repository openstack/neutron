# Copyright 2026 Red Hat, LLC
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

import sqlalchemy as sa

from alembic import op

# Replace physical_network NULL with empty string for tunnel segments
# and add unique constraint on (network_type, physical_network,
# segmentation_id).
#
# Revision ID: d4b7e5f2a1c3
# Revises: c7f8d9e0f1a2
# Create Date: 2026-09-29 09:00:00.000000

revision = 'd4b7e5f2a1c3'
down_revision = 'c7f8d9e0f1a2'


def upgrade():
    connection = op.get_bind()

    # Convert NULL physical_network to empty string.  If duplicate
    # tunnel segments exist for the same (network_id, network_type,
    # segment_index), this UPDATE will fail against the existing
    # unique constraint — that indicates data corruption that the
    # operator must resolve manually (the upgrade check
    # ``networksegments_unique_constraint_check`` detects this
    # condition before the migration runs).
    connection.execute(sa.text(
        "UPDATE networksegments SET physical_network = '' "
        "WHERE physical_network IS NULL"))

    # Add unique constraint to prevent duplicate segment allocations
    # at the DB level.  Guard with an existence check so that the
    # migration is idempotent.
    inspector = sa.inspect(connection)
    constraints = {c['name']
                   for c in inspector.get_unique_constraints(
                       'networksegments')}
    if 'uniq_networksegment0type0physnet0segid' not in constraints:
        op.create_unique_constraint(
            'uniq_networksegment0type0physnet0segid',
            'networksegments',
            ['network_type', 'physical_network', 'segmentation_id'])
