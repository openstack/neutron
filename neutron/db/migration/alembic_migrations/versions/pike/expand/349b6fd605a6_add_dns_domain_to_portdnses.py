# Copyright 2017 IBM
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
from neutron_lib.db import constants
import sqlalchemy as sa

"""Add dns_domain to portdnses

Revision ID: 349b6fd605a6
Revises: c8c222d42aa9
Create Date: 2017-04-15 00:22:47.618593

"""

# revision identifiers, used by Alembic.
revision = '349b6fd605a6'
down_revision = 'c8c222d42aa9'


def upgrade():
    op.add_column('portdnses',
                  sa.Column('dns_domain',
                            sa.String(length=constants.FQDN_FIELD_SIZE),
                            nullable=False,
                            server_default=''))
