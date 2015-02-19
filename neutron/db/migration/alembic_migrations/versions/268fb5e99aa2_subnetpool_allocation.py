# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# All rights reserved.
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

"""Initial operations in support of subnet allocation from a pool

"""

revision = '268fb5e99aa2'
down_revision = '034883111f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('subnets',
                  sa.Column('subnetpool_id',
                            sa.String(length=36),
                            nullable=True,
                            index=True))
