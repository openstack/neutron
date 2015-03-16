# Copyright 2015 OpenStack Foundation
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

"""Initial operations to support basic quotas on prefix space in a subnet pool

Revision ID: 28a09af858a8
Revises: 268fb5e99aa2
Create Date: 2015-03-16 10:36:48.810741

"""

# revision identifiers, used by Alembic.
revision = '28a09af858a8'
down_revision = '268fb5e99aa2'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('subnetpools',
                  sa.Column('default_quota',
                            sa.Integer(),
                            nullable=True))
