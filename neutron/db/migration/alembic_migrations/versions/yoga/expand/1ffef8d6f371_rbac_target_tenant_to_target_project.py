# Copyright 2021 Red Hat Inc.
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

"""migrate RBAC registers from "target_tenant" to "target_project"

Revision ID: 1ffef8d6f371
Revises: 76df7844a8c6
Create Date: 2021-10-28 14:10:20.097125

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1ffef8d6f371'
down_revision = '76df7844a8c6'

_INSPECTOR = None
TABLES = ['networkrbacs', 'qospolicyrbacs', 'securitygrouprbacs',
          'addressscoperbacs', 'subnetpoolrbacs', 'addressgrouprbacs']
DROPPED_UNIQUE_CONSTRAINTS = [
    'uniq_networkrbacs0tenant_target0object_id0action',
    'qospolicyrbacs_target_tenant_object_id_action_key',  # PSQL
    'target_tenant',  # MySQL, name provided by mistake
    'uniq_securitygrouprbacs0target_tenant0object_id0action',
    'uniq_address_scopes_rbacs0target_tenant0object_id0action',
    'uniq_subnetpools_rbacs0target_tenant0object_id0action',
    'uniq_address_groups_rbacs0target_tenant0object_id0action']


def get_inspector():
    global _INSPECTOR
    if _INSPECTOR:
        return _INSPECTOR
    else:
        _INSPECTOR = sa.inspect(op.get_bind())

    return _INSPECTOR


def get_columns(table):
    inspector = get_inspector()
    return inspector.get_columns(table)


def get_data():
    output = []
    for table in TABLES:
        for column in get_columns(table):
            if column['name'] == 'target_tenant':
                output.append((table, column))

    return output


def delete_unique_constraint(table):
    inspector = get_inspector()
    unique_constraints = inspector.get_unique_constraints(table)
    for constraint in unique_constraints:
        op.drop_constraint(
            constraint_name=constraint['name'],
            table_name=table,
            type_='unique')


def add_unique_constraint(table):
    op.create_unique_constraint(
        constraint_name='uniq_%s0target_project0object_id0action' % table,
        table_name=table, columns=['target_project', 'object_id', 'action'])


def alter_column(table, column):
    op.alter_column(
        table_name=table,
        column_name='target_tenant',
        new_column_name='target_project',
        existing_type=sa.String(length=255),
        existing_nullable=column['nullable'])


def recreate_index(table):
    inspector = get_inspector()
    indexes = inspector.get_indexes(table)
    index_name = 'ix_' + table + '_target_tenant'
    for idx in (idx for idx in indexes if idx['name'] == index_name):
        old_name = idx['name']
        new_name = old_name.replace('target_tenant', 'target_project')
        op.drop_index(index_name=op.f(old_name), table_name=table)
        op.create_index(new_name, table, ['target_project'])


def upgrade():
    for table, column in get_data():
        delete_unique_constraint(table)
        alter_column(table, column)
        recreate_index(table)
        add_unique_constraint(table)


def expand_drop_exceptions():
    """Drop the unique constraints and "*_target_tenant" keys

    In order to rename the ``TABLES`` column name from "target_tenant" to
    "target_project", it is needed to drop any constraint related to this
    column. For all tables in ``TABLES``, this migration will drop:
    - Unique constraint "uniq_<table>0target_tenant0object_id0action"
    - Key "ix_<table>_target_tenant"

    Once the column name is changed, both the unique constraint and the key are
    created again.
    """
    return {
        sa.UniqueConstraint: DROPPED_UNIQUE_CONSTRAINTS,
        sa.Index: TABLES
    }
