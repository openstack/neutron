# Copyright 2015 Huawei Technologies India Pvt. Ltd.
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

"""address scope support in subnetpool

Revision ID: 1b4c6e320f79
Revises: 1c844d1677f7
Create Date: 2015-07-03 09:48:39.491058

"""

# revision identifiers, used by Alembic.
revision = '1b4c6e320f79'
down_revision = '1c844d1677f7'


def upgrade():
    op.add_column('subnetpools',
                  sa.Column('address_scope_id',
                            sa.String(length=36),
                            nullable=True))
