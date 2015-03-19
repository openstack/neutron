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

"""set_admin_state_up_not_null_ml2

Revision ID: d06e871c0d5
Revises: 2447ad0e9585
Create Date: 2014-03-21 17:22:20.545186

"""

# revision identifiers, used by Alembic.
revision = 'd06e871c0d5'
down_revision = '4eca4a84f08a'

# This migration will be executed only if the neutron DB schema
# contains the tables for the ML2 plugin brocade driver.
# This migration will be skipped when executed in offline mode.


import sqlalchemy as sa

from neutron.db import migration


@migration.skip_if_offline
def upgrade():
    migration.alter_column_if_exists(
        'ml2_brocadeports', 'admin_state_up',
        nullable=False,
        existing_type=sa.Boolean)
