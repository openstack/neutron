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

from alembic import op
import sqlalchemy

"""Rename ml2_network_segments table

Revision ID: 89ab9a816d70
Revises: 7bbb25278f53
Create Date: 2016-03-22 00:22:47.618593

"""

# revision identifiers, used by Alembic.
revision = '89ab9a816d70'
down_revision = '7bbb25278f53'


TABLE_NAME = 'ml2_port_binding_levels'
OLD_REFERRED_TABLE_NAME = 'ml2_network_segments'
NEW_REFERRED_TABLE_NAME = 'networksegments'


def upgrade():
    fk_name = delete_foreign_key_constraint()
    op.rename_table(OLD_REFERRED_TABLE_NAME, NEW_REFERRED_TABLE_NAME)
    op.create_foreign_key(
        constraint_name=fk_name,
        source_table=TABLE_NAME,
        referent_table=NEW_REFERRED_TABLE_NAME,
        local_cols=['segment_id'],
        remote_cols=['id'],
        ondelete="SET NULL"
    )


def delete_foreign_key_constraint():
    inspector = sqlalchemy.inspect(op.get_bind())
    fk_constraints = inspector.get_foreign_keys(TABLE_NAME)
    for fk in fk_constraints:
        if fk['referred_table'] == OLD_REFERRED_TABLE_NAME:
            op.drop_constraint(
                constraint_name=fk['name'],
                table_name=TABLE_NAME,
                type_='foreignkey'
            )
            return fk['name']
