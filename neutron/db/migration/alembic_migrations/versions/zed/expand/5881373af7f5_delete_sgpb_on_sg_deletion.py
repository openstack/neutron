# Copyright 2022 OpenStack Foundation
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

from neutron.db import migration

"""delete SecurityGroupPortBinding on security group deletion

Revision ID: 5881373af7f5
Revises: 21ff98fabab1
Create Date: 2022-08-10 07:17:00.360917

"""

# revision identifiers, used by Alembic.
revision = '5881373af7f5'
down_revision = '21ff98fabab1'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.ZED]

TABLE_NAME = 'securitygroupportbindings'


def upgrade():
    inspector = sa.inspect(op.get_bind())
    fk_constraints = inspector.get_foreign_keys(TABLE_NAME)
    for fk in fk_constraints:
        if fk['constrained_columns'] == ['security_group_id']:
            migration.remove_foreign_keys(TABLE_NAME, [fk])
            fk['options']['ondelete'] = 'CASCADE'
            migration.create_foreign_keys(TABLE_NAME, [fk])
            return


def expand_drop_exceptions():
    """Drop the foreign key from "securitygroupportbindings" table

    In order to change the foreign key "security_group_id" from the table
    "securitygroupportbindings" and set the condition "ondelete=CASCADE",
    it is needed first to drop it, modify it and readd it again.
    """
    return {
        sa.ForeignKeyConstraint: [
            'securitygroupportbindings_ibfk_2',  # MySQL name
            'securitygroupportbindings_security_group_id_fkey',  # PGSQL name
        ],
    }
