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

"""weight_scheduler

Revision ID: 1955efc66455
Revises: 35a0f3365720
Create Date: 2015-03-12 22:11:37.607390

"""

# revision identifiers, used by Alembic.
revision = '1955efc66455'
down_revision = '35a0f3365720'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('agents',
                  sa.Column('load', sa.Integer(),
                            server_default='0', nullable=False))
