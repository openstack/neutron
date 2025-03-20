# Copyright 2025 Red Hat, Inc.
# All Rights Reserved.
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

from importlib import util as imp_util
import os

from neutron.db import migration as db_migration
from neutron.db.migration.alembic_migrations.versions import kilo_initial
from neutron.db.migration import cli as migration_cli
from neutron.tests import base


class TestDBMigration(base.BaseTestCase):

    def test_current_release_is_in_releases(self):
        self.assertIn(migration_cli.CURRENT_RELEASE,
                      migration_cli.RELEASES)

    def test_current_release_not_in_neutron_milestones(self):
        self.assertNotIn(migration_cli.CURRENT_RELEASE,
                         db_migration.NEUTRON_MILESTONES)

    def test_neutron_milestones_present_in_releases(self):
        # The RELEASES tuple must have all NEUTRON_MILESTONES values plus
        # the CURRENT_RELEASE one.
        milestones = set(db_migration.NEUTRON_MILESTONES)
        releases = set(migration_cli.RELEASES)
        self.assertEqual({migration_cli.CURRENT_RELEASE},
                         releases - milestones)

    def test_check_all_milestones_are_tagged(self):
        neutron_milestones = set(db_migration.NEUTRON_MILESTONES)
        initial_migration_file = os.path.abspath(kilo_initial.__file__)
        base_dir_migrations = os.path.dirname(initial_migration_file)
        for subdir, dirs, mod_files in os.walk(base_dir_migrations):
            # Read all files present in
            # ``./neutron/db/migration/alembic_migrations``
            for mod_file in mod_files:
                mod_name, file_ext = os.path.splitext(
                    os.path.split(mod_file)[-1])
                mod_path = os.path.join(subdir, mod_file)
                last_dir = os.path.basename(subdir)
                # This test only checks the expand migrations.
                if (file_ext.lower() == '.py' and
                        not mod_name.startswith('_') and
                        last_dir == 'expand'):
                    spec = imp_util.spec_from_file_location(mod_name, mod_path)
                    mod = imp_util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    neutron_milestone = getattr(mod, 'neutron_milestone', None)
                    if neutron_milestone:
                        # If the file has the ``neutron_milestone`` variable,
                        # check that is present in the ``NEUTRON_MILESTONES``
                        # list.
                        neutron_milestone = neutron_milestone.pop()
                        try:
                            neutron_milestones.remove(neutron_milestone)
                        except KeyError:
                            self.fail(
                                'Milestone %s not present in the milestones '
                                'list; this milestone has been defined more '
                                'than once')

        # Once all expand migration scripts have been read, all migration
        # milestones must be removed from the ``NEUTRON_MILESTONES`` list.
        self.assertEqual(set(), neutron_milestones)
