# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation
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

"""grizzly

Revision ID: grizzly
Revises: 1341ed32cc1e
Create Date: 2013-03-12 23:59:59.000000

"""

# revision identifiers, used by Alembic.
revision = 'grizzly'
down_revision = '1341ed32cc1e'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['*']


def upgrade(active_plugin=None, options=None):
    """A no-op migration for marking the Grizzly release."""
    pass


def downgrade(active_plugin=None, options=None):
    """A no-op migration for marking the Grizzly release."""
    pass
