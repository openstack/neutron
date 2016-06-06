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

"""Add index on trunk_id to subports model """

revision = '0e877ec3cba3'
down_revision = '30107ab6a3ee'

from alembic import op


def upgrade():
    op.create_index('ix_subports_trunk_id',
                    'subports',
                    ['trunk_id'],
                    unique=False)
