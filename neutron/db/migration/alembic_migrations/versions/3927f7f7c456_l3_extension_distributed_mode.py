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

"""L3 extension distributed mode

Revision ID: 3927f7f7c456
Revises: db_healing
Create Date: 2014-04-02 23:26:19.303633
"""

# revision identifiers, used by Alembic.
revision = '3927f7f7c456'
down_revision = 'db_healing'

from alembic import op
import sqlalchemy as sa


def upgrade():
    context = op.get_context()
    op.create_table(
        'router_extra_attributes',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('distributed', sa.Boolean(), nullable=False,
                  server_default=sa.sql.false()),
        sa.ForeignKeyConstraint(
            ['router_id'], ['routers.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id')
    )
    if context.bind.dialect.name == 'ibm_db_sa':
        # NOTE(mriedem): DB2 stores booleans as 0 and 1.
        op.execute("INSERT INTO router_extra_attributes "
              "SELECT id as router_id, "
              "0 as distributed from routers")
    else:
        op.execute("INSERT INTO router_extra_attributes "
              "SELECT id as router_id, "
              "False as distributed from routers")
