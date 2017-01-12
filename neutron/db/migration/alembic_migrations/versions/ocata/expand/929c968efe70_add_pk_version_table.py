# Copyright 2017 OpenStack Foundation
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

"""add_pk_version_table

Revision ID: 929c968efe70
Revises: 5cd92597d11d
Create Date: 2017-01-12 07:17:33.677770

"""

# revision identifiers, used by Alembic.
revision = '929c968efe70'
down_revision = '5cd92597d11d'


from neutron.db import migration


def upgrade():
    migration.pk_on_alembic_version_table()
