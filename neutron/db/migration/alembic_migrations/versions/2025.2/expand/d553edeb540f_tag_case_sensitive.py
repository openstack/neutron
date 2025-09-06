# Copyright 2025 OpenStack Foundation
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
from oslo_log import log as logging
from sqlalchemy import exc

from neutron.db import migration


LOG = logging.getLogger(__name__)


# Make "tag" resources case sensitive, using collate/charset
# "utf8mb4_bin/utf8mb4"
#
# Revision ID: d553edeb540f
# Revises: ad80a9f07c5c
# Create Date: 2025-06-17 23:13:24.272747

# revision identifiers, used by Alembic.
revision = 'd553edeb540f'
down_revision = 'ad80a9f07c5c'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.RELEASE_2025_2]


def upgrade():
    try:
        op.execute('ALTER TABLE tags CONVERT TO CHARACTER SET utf8mb4 '
                   'COLLATE utf8mb4_bin')
        op.execute('ALTER TABLE tags CHARACTER SET utf8mb4 '
                   'COLLATE utf8mb4_bin')
    except exc.OperationalError as _exc:
        if 'Unknown collation' in str(_exc):
            LOG.error('Collation "utf8mb4_bin" does not exist; the Neutron '
                      '"tag" table will remain case insensitive.')
        else:
            raise _exc
