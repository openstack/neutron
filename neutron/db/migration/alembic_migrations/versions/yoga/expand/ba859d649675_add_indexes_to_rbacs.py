# Copyright 2021 OpenStack Foundation
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


"""Add indexes to RBACs

Revision ID: ba859d649675
Revises: c181bb1d89e4
Create Date: 2021-09-20 15:22:04.668376

"""

# revision identifiers, used by Alembic.
revision = 'ba859d649675'
down_revision = 'c181bb1d89e4'

OBJECTS = ('network', 'qospolicy', 'securitygroup', 'addressscope',
           'subnetpool', 'addressgroup')
COLUMNS = ('target_tenant', 'action')
_INSPECTOR = None


def get_inspector():
    global _INSPECTOR
    if _INSPECTOR:
        return _INSPECTOR

    _INSPECTOR = sa.inspect(op.get_bind())

    return _INSPECTOR


def has_index(table, column):
    """Check if the table has an index *using only* the column name provided"""
    inspector = get_inspector()
    table_indexes = inspector.get_indexes(table)
    for index in table_indexes:
        if [column] == index['column_names']:
            return True
    return False


def upgrade():
    for object in OBJECTS:
        table = object + 'rbacs'
        ix = 'ix_' + table + '_'
        for column in COLUMNS:
            if not has_index(table, column):
                op.create_index(op.f(ix + column), table, [column],
                                unique=False)
