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

from neutron_lib.db import constants as db_const

from neutron.db import migration

"""fip qos

Revision ID: 594422d373ee
Revises: 7d32f979895f
Create Date: 2016-04-26 17:16:10.323756

"""

# revision identifiers, used by Alembic.
revision = '594422d373ee'
down_revision = '7d32f979895f'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.QUEENS]


def upgrade():
    op.create_table(
        'qos_fip_policy_bindings',
        sa.Column('policy_id',
                  sa.String(length=db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('fip_id',
                  sa.String(length=db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey('floatingips.id', ondelete='CASCADE'),
                  nullable=False, unique=True))
