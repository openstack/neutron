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
from neutron_lib import constants as n_const
from neutron_lib.db import constants as db_const
import sqlalchemy as sa


"""port_numa_affinity_policy

Revision ID: 532aa95457e2
Revises: I38991de2b4
Create Date: 2020-07-10 14:59:18.868245

"""

# revision identifiers, used by Alembic.
revision = '532aa95457e2'
down_revision = 'I38991de2b4'


def upgrade():
    op.create_table('portnumaaffinitypolicies',
                    sa.Column('port_id',
                              sa.String(length=db_const.UUID_FIELD_SIZE),
                              sa.ForeignKey('ports.id', ondelete='CASCADE'),
                              primary_key=True),
                    sa.Column('numa_affinity_policy',
                              sa.Enum(*n_const.PORT_NUMA_POLICIES,
                                      name='numa_affinity_policy'))
                    )
