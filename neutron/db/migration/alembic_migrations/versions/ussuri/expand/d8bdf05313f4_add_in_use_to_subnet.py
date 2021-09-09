# Copyright 2020 Red Hat, Inc.
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


"""add in_use to subnet

Revision ID: d8bdf05313f4
Revises: e88badaa9591
Create Date: 2020-03-13 17:15:38.462751

"""

# revision identifiers, used by Alembic.
revision = 'd8bdf05313f4'
down_revision = 'e88badaa9591'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.USSURI]

TABLE = 'subnets'
COLUMN_IN_USE = 'in_use'


def upgrade():
    inspector = sa.inspect(op.get_bind())
    # NOTE(ralonsoh): bug #1865891 is present in stable releases. Although is
    # not possible to backport a patch implementing a DB change [1], we are
    # planning to migrate this patch to a stable branch in a private
    # repository. This check will not affect the current revision (this table
    # column does not exist) and help us in the maintenance of our stable
    # branches.
    # [1] https://docs.openstack.org/project-team-guide/
    #     stable-branches.html#review-guidelines
    if COLUMN_IN_USE not in [column['name'] for column
                             in inspector.get_columns(TABLE)]:
        op.add_column(TABLE,
                      sa.Column(COLUMN_IN_USE,
                                sa.Boolean(),
                                server_default=sa.sql.false(),
                                nullable=False))
