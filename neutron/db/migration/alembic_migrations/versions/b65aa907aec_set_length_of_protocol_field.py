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

"""set_length_of_protocol_field

Revision ID: b65aa907aec
Revises: 1e5dd1d09b22
Create Date: 2014-03-21 16:30:10.626649

"""

# revision identifiers, used by Alembic.
revision = 'b65aa907aec'
down_revision = '1e5dd1d09b22'

# This migration will be executed only if then Neutron db contains tables for
# the firewall service plugin
# This migration will not be executed in offline mode

import sqlalchemy as sa

from neutron.db import migration


@migration.skip_if_offline
def upgrade():
    migration.alter_column_if_exists(
        'firewall_rules', 'protocol',
        type_=sa.String(40),
        existing_nullable=True)
