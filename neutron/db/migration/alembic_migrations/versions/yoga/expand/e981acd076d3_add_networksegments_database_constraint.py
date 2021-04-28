# Copyright 2021 OpenStack Foundation
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


"""Add NetworkSegments database constraint

Revision ID: e981acd076d3
Revises: ba859d649675
Create Date: 2021-04-23 16:01:01.320910

"""

# revision identifiers, used by Alembic.
revision = 'e981acd076d3'
down_revision = 'ba859d649675'


def upgrade():
    op.create_unique_constraint(
        'uniq_networksegment0network_id0network_type0physical_network',
        'networksegments',
        ['network_id', 'network_type', 'physical_network']
    )
