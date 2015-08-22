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

import copy
import os
import sys

from alembic import config as alembic_config
import fixtures
import mock
import pkg_resources

from neutron.db import migration
from neutron.db.migration import cli
from neutron.tests import base


class FakeConfig(object):
    service = ''


class FakeRevision(object):
    path = 'fakepath'

    def __init__(self, labels=None, down_revision=None):
        if not labels:
            labels = set()
        self.branch_labels = labels
        self.down_revision = down_revision


class MigrationEntrypointsMemento(fixtures.Fixture):
    '''Create a copy of the migration entrypoints map so it can be restored
       during test cleanup.
    '''

    def _setUp(self):
        self.ep_backup = {}
        for proj, ep in cli.migration_entrypoints.items():
            self.ep_backup[proj] = copy.copy(ep)
        self.addCleanup(self.restore)

    def restore(self):
        cli.migration_entrypoints = self.ep_backup


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

        def mocked_root_dir(cfg):
            return os.path.join('/fake/dir', cli._get_project_base(cfg))
        mock_root = mock.patch.object(cli, '_get_package_root_dir').start()
        mock_root.side_effect = mocked_root_dir
        # Avoid creating fake directories
        mock.patch('neutron.common.utils.ensure_dir').start()

        # Set up some configs and entrypoints for tests to chew on
        self.configs = []
        self.projects = ('neutron', 'networking-foo', 'neutron-fwaas')
        ini = os.path.join(os.path.dirname(cli.__file__), 'alembic.ini')
        self.useFixture(MigrationEntrypointsMemento())
        cli.migration_entrypoints = {}
        for project in self.projects:
            config = alembic_config.Config(ini)
            config.set_main_option('neutron_project', project)
            module_name = project.replace('-', '_') + '.db.migration'
            attrs = ('alembic_migrations',)
            script_location = ':'.join([module_name, attrs[0]])
            config.set_main_option('script_location', script_location)
            self.configs.append(config)
            entrypoint = pkg_resources.EntryPoint(project,
                                                  module_name,
                                                  attrs=attrs)
            cli.migration_entrypoints[project] = entrypoint

    def _main_test_helper(self, argv, func_name, exp_args=(), exp_kwargs=[{}]):
        with mock.patch.object(sys, 'argv', argv),\
            mock.patch.object(cli, 'run_sanity_checks'),\
            mock.patch.object(cli, 'validate_labels'):

            cli.main()
            self.do_alembic_cmd.assert_has_calls(
                [mock.call(mock.ANY, func_name, *exp_args, **kwargs)
                 for kwargs in exp_kwargs]
            )

    def test_stamp(self):
        self._main_test_helper(
            ['prog', 'stamp', 'foo'],
            'stamp',
            ('foo',),
            [{'sql': False}]
        )

        self._main_test_helper(
            ['prog', 'stamp', 'foo', '--sql'],
            'stamp',
            ('foo',),
            [{'sql': True}]
        )

    def test_current(self):
        self._main_test_helper(['prog', 'current'], 'current')

    def test_history(self):
        self._main_test_helper(['prog', 'history'], 'history')

    def test_check_migration(self):
        with mock.patch.object(cli, 'validate_heads_file') as validate:
            self._main_test_helper(['prog', 'check_migration'], 'branches')
            self.assertEqual(len(self.projects), validate.call_count)

    def _test_database_sync_revision(self, separate_branches=True):
        with mock.patch.object(cli, 'update_heads_file') as update,\
                mock.patch.object(cli, '_use_separate_migration_branches',
                                  return_value=separate_branches):
            if separate_branches:
                mock.patch('os.path.exists').start()
                expected_kwargs = [
                    {'message': 'message', 'sql': False, 'autogenerate': True,
                     'version_path':
                         cli._get_version_branch_path(config, branch),
                     'head': cli._get_branch_head(branch)}
                    for config in self.configs
                    for branch in cli.MIGRATION_BRANCHES]
            else:
                expected_kwargs = [{
                    'message': 'message', 'sql': False, 'autogenerate': True,
                }]
            self._main_test_helper(
                ['prog', 'revision', '--autogenerate', '-m', 'message'],
                'revision',
                (), expected_kwargs
            )
            self.assertEqual(len(self.projects), update.call_count)
            update.reset_mock()

            for kwarg in expected_kwargs:
                kwarg['autogenerate'] = False
                kwarg['sql'] = True

            self._main_test_helper(
                ['prog', 'revision', '--sql', '-m', 'message'],
                'revision',
                (), expected_kwargs
            )
            self.assertEqual(len(self.projects), update.call_count)

    def test_database_sync_revision(self):
        self._test_database_sync_revision()

    def test_database_sync_revision_no_branches(self):
        # Test that old branchless approach is still supported
        self._test_database_sync_revision(separate_branches=False)

    def test_upgrade(self):
        self._main_test_helper(
            ['prog', 'upgrade', '--sql', 'head'],
            'upgrade',
            ('heads',),
            [{'sql': True}]
        )

        self._main_test_helper(
            ['prog', 'upgrade', '--delta', '3'],
            'upgrade',
            ('+3',),
            [{'sql': False}]
        )

        self._main_test_helper(
            ['prog', 'upgrade', 'kilo', '--delta', '3'],
            'upgrade',
            ('kilo+3',),
            [{'sql': False}]
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

    def _test_validate_heads_file_helper(self, heads, file_heads=None,
                                         branchless=False):
        if file_heads is None:
            file_heads = []
        fake_config = self.configs[0]
        with mock.patch('alembic.script.ScriptDirectory.from_config') as fc,\
                mock.patch.object(cli, '_use_separate_migration_branches',
                                  return_value=not branchless):
            fc.return_value.get_heads.return_value = heads
            with mock.patch('six.moves.builtins.open') as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = mock.Mock()
                mock_open.return_value.read.return_value = (
                    '\n'.join(file_heads))

                if all(head in file_heads for head in heads):
                    cli.validate_heads_file(fake_config)
                else:
                    self.assertRaises(
                        SystemExit,
                        cli.validate_heads_file,
                        fake_config
                    )
                    self.assertTrue(self.mock_alembic_err.called)

                if branchless:
                    mock_open.assert_called_with(
                        cli._get_head_file_path(fake_config))
                else:
                    mock_open.assert_called_with(
                        cli._get_heads_file_path(fake_config))

            fc.assert_called_once_with(fake_config)

    def test_validate_heads_file_multiple_heads(self):
        self._test_validate_heads_file_helper(['a', 'b'])

    def test_validate_heads_file_missing_file(self):
        self._test_validate_heads_file_helper(['a'])

    def test_validate_heads_file_wrong_contents(self):
        self._test_validate_heads_file_helper(['a'], ['b'])

    def test_validate_heads_success(self):
        self._test_validate_heads_file_helper(['a'], ['a'])

    @mock.patch.object(cli, '_use_separate_migration_branches',
                       return_value=False)
    def test_validate_heads_file_branchless_failure(self, *args):
        self._test_validate_heads_file_helper(['a'], ['b'], branchless=True)

    @mock.patch.object(cli, '_use_separate_migration_branches',
                       return_value=False)
    def test_validate_heads_file_branchless_success(self, *args):
        self._test_validate_heads_file_helper(['a'], ['a'], branchless=True)

    def test_update_heads_file_two_heads(self):
        with mock.patch('alembic.script.ScriptDirectory.from_config') as fc:
            heads = ('b', 'a')
            fc.return_value.get_heads.return_value = heads
            with mock.patch('six.moves.builtins.open') as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = mock.Mock()

                cli.update_heads_file(self.configs[0])
                mock_open.return_value.write.assert_called_once_with(
                    '\n'.join(sorted(heads)))

    @mock.patch('os.path.exists')
    @mock.patch('os.remove')
    def test_update_heads_file_success(self, *os_mocks):
        with mock.patch('alembic.script.ScriptDirectory.from_config') as fc:
            heads = ('a', 'b')
            fc.return_value.get_heads.return_value = heads
            with mock.patch('six.moves.builtins.open') as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = mock.Mock()

                cli.update_heads_file(self.configs[0])
                mock_open.return_value.write.assert_called_once_with(
                    '\n'.join(heads))

                old_head_file = cli._get_head_file_path(self.configs[0])
                for mock_ in os_mocks:
                    mock_.assert_called_with(old_head_file)

    def test_get_project_base(self):
        config = alembic_config.Config()
        config.set_main_option('script_location', 'a.b.c:d')
        proj_base = cli._get_project_base(config)
        self.assertEqual('a', proj_base)

    def test_get_root_versions_dir(self):
        config = alembic_config.Config()
        config.set_main_option('script_location', 'a.b.c:d')
        versions_dir = cli._get_root_versions_dir(config)
        self.assertEqual('/fake/dir/a/a/b/c/d/versions', versions_dir)

    def test_get_subproject_script_location(self):
        foo_ep = cli._get_subproject_script_location('networking-foo')
        expected = 'networking_foo.db.migration:alembic_migrations'
        self.assertEqual(expected, foo_ep)

    def test_get_subproject_script_location_not_installed(self):
        self.assertRaises(
            SystemExit, cli._get_subproject_script_location, 'not-installed')

    def test_get_service_script_location(self):
        fwaas_ep = cli._get_service_script_location('fwaas')
        expected = 'neutron_fwaas.db.migration:alembic_migrations'
        self.assertEqual(expected, fwaas_ep)

    def test_get_service_script_location_not_installed(self):
        self.assertRaises(
            SystemExit, cli._get_service_script_location, 'myaas')

    def test_get_subproject_base_not_installed(self):
        self.assertRaises(
            SystemExit, cli._get_subproject_base, 'not-installed')

    def test__compare_labels_ok(self):
        labels = {'label1', 'label2'}
        fake_revision = FakeRevision(labels)
        cli._compare_labels(fake_revision, {'label1', 'label2'})

    def test__compare_labels_fail_unexpected_labels(self):
        labels = {'label1', 'label2', 'label3'}
        fake_revision = FakeRevision(labels)
        self.assertRaises(
            SystemExit,
            cli._compare_labels, fake_revision, {'label1', 'label2'})

    @mock.patch.object(cli, '_compare_labels')
    def test__validate_single_revision_labels_branchless_fail_different_labels(
        self, compare_mock):

        fake_down_revision = FakeRevision()
        fake_revision = FakeRevision(down_revision=fake_down_revision)

        script_dir = mock.Mock()
        script_dir.get_revision.return_value = fake_down_revision
        cli._validate_single_revision_labels(script_dir, fake_revision,
                                             label=None)

        expected_labels = set()
        compare_mock.assert_has_calls(
            [mock.call(revision, expected_labels)
             for revision in (fake_revision, fake_down_revision)]
        )

    @mock.patch.object(cli, '_compare_labels')
    def test__validate_single_revision_labels_branches_fail_different_labels(
        self, compare_mock):

        fake_down_revision = FakeRevision()
        fake_revision = FakeRevision(down_revision=fake_down_revision)

        script_dir = mock.Mock()
        script_dir.get_revision.return_value = fake_down_revision
        cli._validate_single_revision_labels(
            script_dir, fake_revision, label='fakebranch')

        expected_labels = {'fakebranch'}
        compare_mock.assert_has_calls(
            [mock.call(revision, expected_labels)
             for revision in (fake_revision, fake_down_revision)]
        )

    @mock.patch.object(cli, '_validate_single_revision_labels')
    def test__validate_revision_validates_branches(self, validate_mock):
        script_dir = mock.Mock()
        fake_revision = FakeRevision()
        branch = cli.MIGRATION_BRANCHES[0]
        fake_revision.path = os.path.join('/fake/path', branch)
        cli._validate_revision(script_dir, fake_revision)
        validate_mock.assert_called_with(
            script_dir, fake_revision, label=branch)

    @mock.patch.object(cli, '_validate_single_revision_labels')
    def test__validate_revision_validates_branchless_migrations(
        self, validate_mock):

        script_dir = mock.Mock()
        fake_revision = FakeRevision()
        cli._validate_revision(script_dir, fake_revision)
        validate_mock.assert_called_with(script_dir, fake_revision)

    @mock.patch.object(cli, '_validate_revision')
    @mock.patch('alembic.script.ScriptDirectory.walk_revisions')
    def test_validate_labels_walks_thru_all_revisions(
        self, walk_mock, validate_mock):

        revisions = [mock.Mock() for i in range(10)]
        walk_mock.return_value = revisions
        cli.validate_labels(self.configs[0])
        validate_mock.assert_has_calls(
            [mock.call(mock.ANY, revision) for revision in revisions]
        )


class TestSafetyChecks(base.BaseTestCase):

    def test_validate_labels(self, *mocks):
        cli.validate_labels(cli.get_neutron_config())
