# Copyright (c) 2015 Thales Services SAS
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

"""Add mac_address unique constraint

Revision ID: 2a1ee2fb59e0
Revises: 41662e32bce2
Create Date: 2015-01-10 11:44:27.550349

"""

# revision identifiers, used by Alembic.
revision = '2a1ee2fb59e0'
down_revision = '41662e32bce2'

from alembic import op

TABLE_NAME = 'ports'
CONSTRAINT_NAME = 'uniq_ports0network_id0mac_address'


def upgrade():
    op.create_unique_constraint(
        name=CONSTRAINT_NAME,
        source=TABLE_NAME,
        local_cols=['network_id', 'mac_address']
    )
