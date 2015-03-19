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

"""add_uniqueconstraint_ipavailability_ranges

Revision ID: 44621190bc02
Revises: juno
Create Date: 2014-09-23 15:14:15.051921

"""

# revision identifiers, used by Alembic.
revision = '44621190bc02'
down_revision = 'juno'

from alembic import op


TABLE_NAME = 'ipavailabilityranges'
UC_1_NAME = 'uniq_ipavailabilityranges0first_ip0allocation_pool_id'
UC_2_NAME = 'uniq_ipavailabilityranges0last_ip0allocation_pool_id'


def upgrade():
    op.create_unique_constraint(
        name=UC_1_NAME,
        source=TABLE_NAME,
        local_cols=['first_ip', 'allocation_pool_id']
    )

    op.create_unique_constraint(
        name=UC_2_NAME,
        source=TABLE_NAME,
        local_cols=['last_ip', 'allocation_pool_id']
    )
