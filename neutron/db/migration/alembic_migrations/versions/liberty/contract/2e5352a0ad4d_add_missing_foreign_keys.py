# Copyright 2015 Red Hat, Inc.
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
import sqlalchemy

from neutron.db import migration

"""Add missing foreign keys

Revision ID: 2e5352a0ad4d
Revises: 2a16083502f3
Create Date: 2015-08-20 12:43:09.110427

"""

# revision identifiers, used by Alembic.
revision = '2e5352a0ad4d'
down_revision = '2a16083502f3'


TABLE_NAME = 'flavorserviceprofilebindings'


def upgrade():
    inspector = sqlalchemy.inspect(op.get_bind())
    fk_constraints = inspector.get_foreign_keys(TABLE_NAME)
    for fk in fk_constraints:
        fk['options']['ondelete'] = 'CASCADE'

    migration.remove_foreign_keys(TABLE_NAME, fk_constraints)
    migration.create_foreign_keys(TABLE_NAME, fk_constraints)
