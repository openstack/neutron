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

"""ml2_type_driver_refactor_dynamic_segments

Revision ID: 236b90af57ab
Revises: 58fe87a01143
Create Date: 2014-08-14 16:22:14.293788

"""

# revision identifiers, used by Alembic.
revision = '236b90af57ab'
down_revision = '58fe87a01143'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column('ml2_network_segments',
                  sa.Column('is_dynamic', sa.Boolean(), nullable=False,
                            server_default=sa.sql.false()))
