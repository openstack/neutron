# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 New Dream Network, LLC (DreamHost)
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

# @author Mark McClain (DreamHost)

import sys

import mock
import unittest2 as unittest

from quantum.db import migration
from quantum.db.migration import cli


class TestDbMigration(unittest.TestCase):
    def test_should_run_plugin_in_list(self):
        self.assertTrue(migration.should_run('foo', ['foo', 'bar']))
        self.assertFalse(migration.should_run('foo', ['bar']))

    def test_should_run_plugin_wildcard(self):
        self.assertTrue(migration.should_run('foo', ['*']))


class TestMain(unittest.TestCase):
    def setUp(self):
        self.process_argv_p = mock.patch.object(cli, 'process_argv')
        self.process_argv = self.process_argv_p.start()

        self.alembic_cmd_p = mock.patch.object(cli, 'alembic_command')
        self.alembic_cmd = self.alembic_cmd_p.start()

    def tearDown(self):
        self.alembic_cmd_p.stop()
        self.process_argv_p.stop()

    def test_main(self):
        self.process_argv.return_value = ('foo', ('bar', ), {'baz': 1})
        cli.main()

        self.process_argv.assert_called_once_with(sys.argv)
        self.alembic_cmd.foo.assert_called_once_with(mock.ANY, 'bar', baz=1)


class TestDatabaseSync(unittest.TestCase):
    def test_process_argv_stamp(self):
        self.assertEqual(
            ('stamp', ('foo',), {'sql': False}),
            cli.process_argv(['prog', 'stamp', 'foo']))

        self.assertEqual(
            ('stamp', ('foo',), {'sql': True}),
            cli.process_argv(['prog', 'stamp', '--sql', 'foo']))

    def test_process_argv_current(self):
        self.assertEqual(
            ('current', (), {}),
            cli.process_argv(['prog', 'current']))

    def test_process_argv_history(self):
        self.assertEqual(
            ('history', (), {}),
            cli.process_argv(['prog', 'history']))

    def test_process_argv_check_migration(self):
        self.assertEqual(
            ('branches', (), {}),
            cli.process_argv(['prog', 'check_migration']))

    def test_database_sync_revision(self):
        expected = (
            'revision',
            (),
            {'message': 'message', 'sql': False, 'autogenerate': True}
        )

        self.assertEqual(
            cli.process_argv(
                ['prog', 'revision', '-m', 'message', '--autogenerate']
            ),
            expected
        )

    def test_database_sync_upgrade(self):
        self.assertEqual(
            cli.process_argv(['prog', 'upgrade', 'head']),
            ('upgrade', ('head', ), {'sql': False})
        )

        self.assertEqual(
            cli.process_argv(['prog', 'upgrade', '--delta', '3']),
            ('upgrade', ('+3', ), {'sql': False})
        )

    def test_database_sync_downgrade(self):
        self.assertEqual(
            cli.process_argv(['prog', 'downgrade', 'folsom']),
            ('downgrade', ('folsom', ), {'sql': False})
        )

        self.assertEqual(
            cli.process_argv(['prog', 'downgrade', '--delta', '2']),
            ('downgrade', ('-2', ), {'sql': False})
        )
