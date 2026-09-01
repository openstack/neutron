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

from neutron.db import migration

# Add subnet_bgp_leak_routes table
#
# Revision ID: c7f8d9e0f1a2
# Revises: a1b2c3d4e5f6
# Create Date: 2026-07-21 15:15:00.000000

# revision identifiers, used by Alembic.
revision = 'c7f8d9e0f1a2'
down_revision = 'a1b2c3d4e5f6'


def upgrade():
    migration.create_table_if_not_exists(
        'subnet_bgp_leak_routes',
        sa.Column('subnet_id', sa.String(length=36),
                  sa.ForeignKey('subnets.id', ondelete='CASCADE'),
                  primary_key=True))
