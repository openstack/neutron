# Copyright 2024 OpenStack Foundation
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

from neutron_lib import constants
import sqlalchemy as sa

from neutron.db import migration


# Add NUMA policy 'socket'
#
# Revision ID: 175fa80908e1
# Revises: 0e6eff810791
# Create Date: 2024-02-24 10:25:52.418502

# revision identifiers, used by Alembic.
revision = '175fa80908e1'
down_revision = '0e6eff810791'

table = 'portnumaaffinitypolicies'
new_enum = sa.Enum(*constants.PORT_NUMA_POLICIES,
                   name='numa_affinity_policy')


def upgrade():
    migration.alter_enum_add_value(table, 'numa_affinity_policy', new_enum,
                                   True)
