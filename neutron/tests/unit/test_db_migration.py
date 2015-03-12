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

import sys

import mock

from neutron.db import migration
from neutron.db.migration import cli
from neutron.tests import base


class TestDbMigration(base.BaseTestCase):

    def setUp(self):
        super(TestDbMigration, self).setUp()
        mock.patch('alembic.op.get_bind').start()
        self.mock_alembic_is_offline = mock.patch(
            'alembic.context.is_offline_mode', return_value=False).start()
        self.mock_alembic_is_offline.return_value = False
        self.mock_sa_inspector = mock.patch(
            'sqlalchemy.engine.reflection.Inspector').start()

    def _prepare_mocked_sqlalchemy_inspector(self):
        mock_inspector = mock.MagicMock()
        mock_inspector.get_table_names.return_value = ['foo', 'bar']
        mock_inspector.get_columns.return_value = [{'name': 'foo_column'},
                                                   {'name': 'bar_column'}]
        self.mock_sa_inspector.from_engine.return_value = mock_inspector

    def test_schema_has_table(self):
        self._prepare_mocked_sqlalchemy_inspector()
        self.assertTrue(migration.schema_has_table('foo'))

    def test_schema_has_table_raises_if_offline(self):
        self.mock_alembic_is_offline.return_value = True
        self.assertRaises(RuntimeError, migration.schema_has_table, 'foo')

    def test_schema_has_column_missing_table(self):
        self._prepare_mocked_sqlalchemy_inspector()
        self.assertFalse(migration.schema_has_column('meh', 'meh'))

    def test_schema_has_column(self):
        self._prepare_mocked_sqlalchemy_inspector()
        self.assertTrue(migration.schema_has_column('foo', 'foo_column'))

    def test_schema_has_column_raises_if_offline(self):
        self.mock_alembic_is_offline.return_value = True
        self.assertRaises(RuntimeError, migration.schema_has_column,
                          'foo', 'foo_col')

    def test_schema_has_column_missing_column(self):
        self._prepare_mocked_sqlalchemy_inspector()
        self.assertFalse(migration.schema_has_column(
            'foo', column_name='meh'))


class TestCli(base.BaseTestCase):
    def setUp(self):
        super(TestCli, self).setUp()
        self.do_alembic_cmd_p = mock.patch.object(cli, 'do_alembic_command')
        self.do_alembic_cmd = self.do_alembic_cmd_p.start()
        self.mock_alembic_err = mock.patch('alembic.util.err').start()
        self.mock_alembic_err.side_effect = SystemExit

    def _main_test_helper(self, argv, func_name, exp_args=(), exp_kwargs={}):
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(
                cli, 'run_sanity_checks'):
            cli.main()
            self.do_alembic_cmd.assert_has_calls(
                [mock.call(mock.ANY, func_name, *exp_args, **exp_kwargs)]
            )

    def test_stamp(self):
        self._main_test_helper(
            ['prog', 'stamp', 'foo'],
            'stamp',
            ('foo',),
            {'sql': False}
        )

        self._main_test_helper(
            ['prog', 'stamp', 'foo', '--sql'],
            'stamp',
            ('foo',),
            {'sql': True}
        )

    def test_current(self):
        self._main_test_helper(['prog', 'current'], 'current')

    def test_history(self):
        self._main_test_helper(['prog', 'history'], 'history')

    def test_check_migration(self):
        with mock.patch.object(cli, 'validate_head_file') as validate:
            self._main_test_helper(['prog', 'check_migration'], 'branches')
            validate.assert_called_once_with(mock.ANY)

    def test_database_sync_revision(self):
        with mock.patch.object(cli, 'update_head_file') as update:
            self._main_test_helper(
                ['prog', 'revision', '--autogenerate', '-m', 'message'],
                'revision',
                (),
                {'message': 'message', 'sql': False, 'autogenerate': True}
            )
            update.assert_called_once_with(mock.ANY)

            update.reset_mock()
            self._main_test_helper(
                ['prog', 'revision', '--sql', '-m', 'message'],
                'revision',
                (),
                {'message': 'message', 'sql': True, 'autogenerate': False}
            )
            update.assert_called_once_with(mock.ANY)

    def test_upgrade(self):
        self._main_test_helper(
            ['prog', 'upgrade', '--sql', 'head'],
            'upgrade',
            ('head',),
            {'sql': True}
        )

        self._main_test_helper(
            ['prog', 'upgrade', '--delta', '3'],
            'upgrade',
            ('+3',),
            {'sql': False}
        )

        self._main_test_helper(
            ['prog', 'upgrade', 'kilo', '--delta', '3'],
            'upgrade',
            ('kilo+3',),
            {'sql': False}
        )

    def assert_command_fails(self, command):
        # Avoid cluttering stdout with argparse error messages
        mock.patch('argparse.ArgumentParser._print_message').start()
        with mock.patch.object(sys, 'argv', command), mock.patch.object(
                cli, 'run_sanity_checks'):
            self.assertRaises(SystemExit, cli.main)

    def test_downgrade_fails(self):
        self.assert_command_fails(['prog', 'downgrade', '--sql', 'juno'])

    def test_upgrade_negative_relative_revision_fails(self):
        self.assert_command_fails(['prog', 'upgrade', '-2'])

    def test_upgrade_negative_delta_fails(self):
        self.assert_command_fails(['prog', 'upgrade', '--delta', '-2'])

    def test_upgrade_rejects_delta_with_relative_revision(self):
        self.assert_command_fails(['prog', 'upgrade', '+2', '--delta', '3'])

    def _test_validate_head_file_helper(self, heads, file_content=None):
        with mock.patch('alembic.script.ScriptDirectory.from_config') as fc:
            fc.return_value.get_heads.return_value = heads
            fc.return_value.get_current_head.return_value = heads[0]
            with mock.patch('__builtin__.open') as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = mock.Mock()
                mock_open.return_value.read.return_value = file_content

                with mock.patch('os.path.isfile') as is_file:
                    is_file.return_value = file_content is not None

                    if file_content in heads:
                        cli.validate_head_file(mock.sentinel.config)
                    else:
                        self.assertRaises(
                            SystemExit,
                            cli.validate_head_file,
                            mock.sentinel.config
                        )
                        self.mock_alembic_err.assert_called_once_with(mock.ANY)
            fc.assert_called_once_with(mock.sentinel.config)

    def test_validate_head_file_multiple_heads(self):
        self._test_validate_head_file_helper(['a', 'b'])

    def test_validate_head_file_missing_file(self):
        self._test_validate_head_file_helper(['a'])

    def test_validate_head_file_wrong_contents(self):
        self._test_validate_head_file_helper(['a'], 'b')

    def test_validate_head_success(self):
        self._test_validate_head_file_helper(['a'], 'a')

    def test_update_head_file_multiple_heads(self):
        with mock.patch('alembic.script.ScriptDirectory.from_config') as fc:
            fc.return_value.get_heads.return_value = ['a', 'b']
            self.assertRaises(
                SystemExit,
                cli.update_head_file,
                mock.sentinel.config
            )
            self.mock_alembic_err.assert_called_once_with(mock.ANY)
            fc.assert_called_once_with(mock.sentinel.config)

    def test_update_head_file_success(self):
        with mock.patch('alembic.script.ScriptDirectory.from_config') as fc:
            fc.return_value.get_heads.return_value = ['a']
            fc.return_value.get_current_head.return_value = 'a'
            with mock.patch('__builtin__.open') as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = mock.Mock()

                cli.update_head_file(mock.sentinel.config)
                mock_open.return_value.write.assert_called_once_with('a')
            fc.assert_called_once_with(mock.sentinel.config)
