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

"""ML2 Refactor for provider networks

Revision ID: 33a3d31845ad
Revises: 236b90af57ab
Create Date: 2014-08-18 14:33:13.124512

"""

# revision identifiers, used by Alembic.
revision = '33a3d31845ad'
down_revision = '236b90af57ab'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):

    op.add_column('ml2_network_segments',
                  sa.Column('provider_segment', sa.Boolean(),
                            server_default=sa.sql.false(),
                            nullable=False))


def downgrade(active_plugins=None, options=None):

    op.drop_column('ml2_network_segments', 'provider_segment')
