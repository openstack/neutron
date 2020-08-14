# Copyright 2020 OpenStack Foundation
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

"""Add source and destination IP prefixes to neutron metering system
Revision ID: I38991de2b4
Revises: fd6107509ccd
Create Date: 2020-08-20 10:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'I38991de2b4'
down_revision = '49d8622c5221'

metering_label_rules_table_name = 'meteringlabelrules'


def upgrade():
    op.add_column(metering_label_rules_table_name,
                  sa.Column('source_ip_prefix', sa.String(64)))
    op.add_column(metering_label_rules_table_name,
                  sa.Column('destination_ip_prefix', sa.String(64)))
