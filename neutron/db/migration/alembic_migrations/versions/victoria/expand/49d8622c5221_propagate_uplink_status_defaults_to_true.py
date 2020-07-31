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
import sqlalchemy as sa


"""propagate_uplink_status_defaults_to_true

Revision ID: 49d8622c5221
Revises: 1ea5dab0897a
Create Date: 2020-07-31 15:27:29.425953

"""

# revision identifiers, used by Alembic.
revision = '49d8622c5221'
down_revision = '1ea5dab0897a'


def upgrade():
    op.alter_column('portuplinkstatuspropagation', 'propagate_uplink_status',
                    existing_type=sa.Boolean(), existing_nullable=False,
                    server_default=sa.sql.true())
