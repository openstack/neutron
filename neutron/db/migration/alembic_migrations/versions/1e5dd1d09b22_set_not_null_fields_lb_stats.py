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

"""set_not_null_fields_lb_stats

Revision ID: 1e5dd1d09b22
Revises: 54f7549a0e5f
Create Date: 2014-03-17 11:00:35.370618

"""

# revision identifiers, used by Alembic.
revision = '1e5dd1d09b22'
down_revision = '54f7549a0e5f'

import sqlalchemy as sa

from neutron.db import migration


@migration.skip_if_offline
def upgrade():
    migration.alter_column_if_exists(
        'poolstatisticss', 'bytes_in',
        nullable=False,
        existing_type=sa.BigInteger())
    migration.alter_column_if_exists(
        'poolstatisticss', 'bytes_out',
        nullable=False,
        existing_type=sa.BigInteger())
    migration.alter_column_if_exists(
        'poolstatisticss', 'active_connections',
        nullable=False,
        existing_type=sa.BigInteger())
    migration.alter_column_if_exists(
        'poolstatisticss', 'total_connections',
        nullable=False,
        existing_type=sa.BigInteger())
