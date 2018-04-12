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

from neutron.db import migration

"""Remove availability ranges."""


revision = '5c85685d616d'
down_revision = '2e0d7a8a1586'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.NEWTON]


def upgrade():
    op.drop_table('ipavailabilityranges')
    op.drop_table('ipamavailabilityranges')
