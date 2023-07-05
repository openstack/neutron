# Copyright 2023 OpenStack Foundation
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

"""de-duplicate indices for ports

Revision ID: b1199a3adbef
Revises: 682c319773d7
Create Date: 2023-06-07 14:31:24.476704

"""

# revision identifiers, used by Alembic.
revision = 'b1199a3adbef'
down_revision = '0aefee21cd87'


TABLE = 'ports'


def upgrade():
    inspector = sa.inspect(op.get_bind())
    indexes = inspector.get_indexes("ports")

    for index in indexes:
        if index['unique'] is False:
            if index['column_names'] == ['network_id', 'mac_address']:
                op.drop_index(index['name'], table_name=TABLE)


def expand_drop_exceptions():
    """Drop the redundant index on network_id+mac_address in ports

    This migration will remove the explicit index on the columns.
    A unique contraint already maintains an index, this second index is
    redundant.
    """
    return {
        sa.Index: [TABLE]
    }
