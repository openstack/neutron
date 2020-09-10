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
from neutron_lib.db import constants as db_const
import sqlalchemy as sa


"""support remote address group in SG rules

Revision ID: a964d94b4677
Revises: f010820fc498
Create Date: 2020-09-10 18:57:21.063935

"""

# revision identifiers, used by Alembic.
revision = 'a964d94b4677'
down_revision = 'f010820fc498'


def upgrade():
    op.add_column('securitygrouprules',
                  sa.Column('remote_address_group_id',
                            sa.String(length=db_const.UUID_FIELD_SIZE),
                            nullable=True))
    op.create_foreign_key(None, 'securitygrouprules', 'address_groups',
                          ['remote_address_group_id'],
                          ['id'], ondelete='CASCADE')
