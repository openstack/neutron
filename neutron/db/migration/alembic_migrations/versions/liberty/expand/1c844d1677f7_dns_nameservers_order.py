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

from alembic import op
import sqlalchemy as sa

"""add order to dnsnameservers

Revision ID: 1c844d1677f7
Revises: 26c371498592
Create Date: 2015-07-21 22:59:03.383850

"""

# revision identifiers, used by Alembic.
revision = '1c844d1677f7'
down_revision = '26c371498592'


def upgrade():
    op.add_column('dnsnameservers',
                  sa.Column('order', sa.Integer(),
                            server_default='0', nullable=False))
