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

"""Include all tables and make migrations unconditional.

Revision ID: db_healing
Revises: 5446f2a45467
Create Date: 2014-05-29 10:52:43.898980

"""

# revision identifiers, used by Alembic.
revision = 'db_healing'
down_revision = '5446f2a45467'

from neutron.db.migration.alembic_migrations import heal_script


def upgrade():
    heal_script.heal()
