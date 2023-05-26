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

from oslo_db.sqlalchemy import utils as db_utils

from neutron.db.migration.alembic_migrations.versions.yoga.expand import \
    ba859d649675_add_indexes_to_rbacs as _migration
from neutron.tests.functional.db import test_migrations


class TestAddIndexesToRbacsMixin(object):
    """Validates binding_index for NetworkDhcpAgentBinding migration."""

    @staticmethod
    def get_index(table_indexes, column):
        for index in table_indexes:
            if [column] == index['column_names']:
                return True
        return False

    def _pre_upgrade_ba859d649675(self, engine):
        for table in _migration.OBJECTS:
            table_indexes = db_utils.get_indexes(engine, table + 'rbacs')
            for column in _migration.COLUMNS:
                self.assertFalse(self.get_index(table_indexes, column))

    def _check_ba859d649675(self, engine, data):
        for table in _migration.OBJECTS:
            table_indexes = db_utils.get_indexes(engine, table + 'rbacs')
            for column in _migration.COLUMNS:
                self.assertTrue(self.get_index(table_indexes, column))


class TestAddIndexesToRbacsMySQL(
        TestAddIndexesToRbacsMixin,
        test_migrations.TestWalkMigrationsMySQL):
    pass


class TestAddIndexesToRbacsPostgreSQL(
        TestAddIndexesToRbacsMixin,
        test_migrations.TestWalkMigrationsPostgreSQL):
    pass
