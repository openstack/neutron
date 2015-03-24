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

"""set_not_null_vlan_id_cisco

Revision ID: 6be312499f9
Revises: d06e871c0d5
Create Date: 2014-03-27 14:38:12.571173

"""

# revision identifiers, used by Alembic.
revision = '6be312499f9'
down_revision = 'd06e871c0d5'

# This migration will be executed only if the neutron DB schema
# contains the tables for the cisco plugin.
# This migration will be skipped when executed in offline mode.

import sqlalchemy as sa

from neutron.db import migration


@migration.skip_if_offline
def upgrade():
    migration.alter_column_if_exists(
        'cisco_nexusport_bindings', 'vlan_id',
        nullable=False,
        existing_type=sa.Integer)
