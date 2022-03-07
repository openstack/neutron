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

import collections
from contextlib import contextmanager
import subprocess

from alembic.ddl import base as alembic_ddl
from alembic import script as alembic_script
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_db.sqlalchemy import test_migrations
from oslo_log import log as logging
from oslotest import base as oslotest_base
import sqlalchemy
from sqlalchemy import event  # noqa
from sqlalchemy.sql import ddl as sqla_ddl

from neutron.db import migration as migration_root
from neutron.db.migration.alembic_migrations import external
from neutron.db.migration import cli as migration
from neutron.db.migration.models import head as head_models
from neutron.tests import base as test_base
from neutron.tests.functional import base as functional_base
from neutron.tests.unit import testlib_api

cfg.CONF.import_opt('core_plugin', 'neutron.conf.common')

CREATION_OPERATIONS = {
    'sqla': (sqla_ddl.CreateIndex,
             sqla_ddl.CreateTable,
             sqla_ddl.CreateColumn,
             ),
    'alembic': (alembic_ddl.AddColumn,
                )
}

DROP_OPERATIONS = {
    'sqla': (sqla_ddl.DropConstraint,
             sqla_ddl.DropIndex,
             sqla_ddl.DropTable,
             ),
    'alembic': (alembic_ddl.DropColumn,
                )
}

LOG = logging.getLogger(__name__)

# NOTE(slaweq): replace alembic_util logging functions used normally with
# olso_log logger to limit output on stdout
migration.log_error = LOG.error
migration.log_warning = LOG.warning
migration.log_info = LOG.info


def upgrade(engine, alembic_config, branch_name='heads'):
    cfg.CONF.set_override('connection', engine.url, group='database')
    migration.do_alembic_command(alembic_config, 'upgrade',
                                 branch_name)


class _TestModelsMigrations(test_migrations.ModelsMigrationsSync):
    '''Test for checking of equality models state and migrations.

    For the opportunistic testing you need to set up a db named
    'openstack_citest' with user 'openstack_citest' and password
    'openstack_citest' on localhost.
    The test will then use that db and user/password combo to run the tests.

    For PostgreSQL on Ubuntu this can be done with the following commands::

        sudo -u postgres psql
        postgres=# create user openstack_citest with createdb login password
                  'openstack_citest';
        postgres=# create database openstack_citest with owner
                   openstack_citest;

    For MySQL on Ubuntu this can be done with the following commands::

        mysql -u root
        >create database openstack_citest;
        >grant all privileges on openstack_citest.* to
         openstack_citest@localhost identified by 'openstack_citest';

    Output is a list that contains information about differences between db and
    models. Output example::

       [('add_table',
         Table('bat', MetaData(bind=None),
               Column('info', String(), table=<bat>), schema=None)),
        ('remove_table',
         Table(u'bar', MetaData(bind=None),
               Column(u'data', VARCHAR(), table=<bar>), schema=None)),
        ('add_column',
         None,
         'foo',
         Column('data', Integer(), table=<foo>)),
        ('remove_column',
         None,
         'foo',
         Column(u'old_data', VARCHAR(), table=None)),
        [('modify_nullable',
          None,
          'foo',
          u'x',
          {'existing_server_default': None,
          'existing_type': INTEGER()},
          True,
          False)]]

    * ``remove_*`` means that there is extra table/column/constraint in db;

    * ``add_*`` means that it is missing in db;

    * ``modify_*`` means that on column in db is set wrong
      type/nullable/server_default. Element contains information:

        - what should be modified,
        - schema,
        - table,
        - column,
        - existing correct column parameters,
        - right value,
        - wrong value.

    This class also contains tests for branches, like that correct operations
    are used in contract and expand branches.

    '''

    BUILD_SCHEMA = False
    TIMEOUT_SCALING_FACTOR = 4

    def setUp(self):
        super(_TestModelsMigrations, self).setUp()
        self.cfg = self.useFixture(config_fixture.Config())
        self.cfg.config(core_plugin='ml2')
        self.alembic_config = migration.get_neutron_config()
        self.alembic_config.neutron_config = cfg.CONF

        # Migration tests can take a long time
        self.useFixture(test_base.Timeout(scaling=self.TIMEOUT_SCALING_FACTOR))

    def db_sync(self, engine):
        upgrade(engine, self.alembic_config)

    def get_engine(self):
        return self.engine

    def get_metadata(self):
        return head_models.get_metadata()

    def include_object(self, object_, name, type_, reflected, compare_to):
        if type_ == 'table' and (name == 'alembic_version' or
                                 name in external.TABLES):
            return False

        return super(_TestModelsMigrations, self).include_object(
            object_, name, type_, reflected, compare_to)

    def filter_metadata_diff(self, diff):
        return list(filter(self.remove_unrelated_errors, diff))

    # Remove some difference that are not mistakes just specific of
    # dialects, etc
    def remove_unrelated_errors(self, element):
        insp = sqlalchemy.inspect(self.get_engine())
        dialect = self.get_engine().dialect.name
        if isinstance(element, tuple):
            if dialect == 'mysql' and element[0] == 'remove_index':
                table_name = element[1].table.name
                for fk in insp.get_foreign_keys(table_name):
                    if fk['name'] == element[1].name:
                        return False
                cols = [c.name for c in element[1].expressions]
                for col in cols:
                    if col in insp.get_pk_constraint(
                            table_name)['constrained_columns']:
                        return False
        else:
            for modified, _, table, column, _, _, new in element:
                if modified == 'modify_default' and dialect == 'mysql':
                    constrained = insp.get_pk_constraint(table)
                    if column in constrained['constrained_columns']:
                        return False
        return True

    def test_upgrade_expand_branch(self):
        # Verify that "command neutron-db-manage upgrade --expand" works
        #  without errors. Check this for both MySQL and PostgreSQL.
        upgrade(self.engine, self.alembic_config,
                branch_name='%s@head' % migration.EXPAND_BRANCH)

    def test_upgrade_contract_branch(self):
        # Verify that "command neutron-db-manage upgrade --contract" works
        # without errors. Check this for both MySQL and PostgreSQL.
        upgrade(self.engine, self.alembic_config,
                branch_name='%s@head' % migration.CONTRACT_BRANCH)

    @contextmanager
    def _listener(self, engine, listener_func):
        try:
            event.listen(engine, 'before_execute', listener_func)
            yield
        finally:
            event.remove(engine, 'before_execute',
                         listener_func)

    def test_branches(self):

        drop_exceptions = collections.defaultdict(list)
        creation_exceptions = collections.defaultdict(list)

        def find_migration_exceptions():
            # Due to some misunderstandings and some conscious decisions,
            # there may be some expand migrations which drop elements and
            # some contract migrations which create elements. These excepted
            # elements must be returned by a method in the script itself.
            # The names of the method must be 'contract_creation_exceptions'
            # or 'expand_drop_exceptions'. The methods must have a docstring
            # explaining the reason for the exception.
            #
            # Here we build lists of the excepted elements and verify that
            # they are documented.
            script = alembic_script.ScriptDirectory.from_config(
                self.alembic_config)
            for m in list(script.walk_revisions(base='base', head='heads')):
                branches = m.branch_labels or []
                if migration.CONTRACT_BRANCH in branches:
                    method_name = 'contract_creation_exceptions'
                    exceptions_dict = creation_exceptions
                elif migration.EXPAND_BRANCH in branches:
                    method_name = 'expand_drop_exceptions'
                    exceptions_dict = drop_exceptions
                else:
                    continue
                get_excepted_elements = getattr(m.module, method_name, None)
                if not get_excepted_elements:
                    continue
                explanation = getattr(get_excepted_elements, '__doc__', "")
                if len(explanation) < 1:
                    self.fail("%s() requires docstring with explanation" %
                              '.'.join([m.module.__name__,
                                        get_excepted_elements.__name__]))
                for sa_type, elements in get_excepted_elements().items():
                    exceptions_dict[sa_type].extend(elements)

        def is_excepted_sqla(clauseelement, exceptions):
            """Identify excepted operations that are allowed for the branch."""
            element = clauseelement.element
            element_name = element.name
            if isinstance(element, sqlalchemy.Index):
                element_name = element.table.name
            for sa_type_, excepted_names in exceptions.items():
                if isinstance(element, sa_type_):
                    if element_name in excepted_names:
                        return True

        def is_excepted_alembic(clauseelement, exceptions):
            """Identify excepted operations that are allowed for the branch."""
            # For alembic the clause is AddColumn or DropColumn
            column = clauseelement.column.name
            table = clauseelement.table_name
            element_name = '.'.join([table, column])
            for alembic_type, excepted_names in exceptions.items():
                if alembic_type == sqlalchemy.Column:
                    if element_name in excepted_names:
                        return True

        def is_allowed(clauseelement, exceptions, disallowed_ops):
            if (isinstance(clauseelement, disallowed_ops['sqla']) and
                    hasattr(clauseelement, 'element')):
                return is_excepted_sqla(clauseelement, exceptions)
            if isinstance(clauseelement, disallowed_ops['alembic']):
                return is_excepted_alembic(clauseelement, exceptions)
            return True

        def check_expand_branch(conn, clauseelement, multiparams, params,
                                execution_options):
            if not is_allowed(clauseelement, drop_exceptions, DROP_OPERATIONS):
                self.fail("Migration in expand branch contains drop command")

        def check_contract_branch(conn, clauseelement, multiparams, params,
                                  execution_options):
            if not is_allowed(clauseelement, creation_exceptions,
                              CREATION_OPERATIONS):
                self.fail("Migration in contract branch contains create "
                          "command")

        find_migration_exceptions()
        engine = self.engine
        cfg.CONF.set_override('connection', engine.url, group='database')

        with engine.begin() as connection:
            self.alembic_config.attributes['connection'] = connection

            # upgrade to latest release first; --expand users are expected to
            # apply all alembic scripts from previous releases before applying
            # the new ones
            for release in migration_root.NEUTRON_MILESTONES:
                release_revisions = migration._find_milestone_revisions(
                    self.alembic_config, release)
                for rev in release_revisions:
                    migration.do_alembic_command(
                        self.alembic_config, 'upgrade', rev[0])

            with self._listener(engine, check_expand_branch):
                migration.do_alembic_command(
                    self.alembic_config, 'upgrade',
                    '%s@head' % migration.EXPAND_BRANCH)

            with self._listener(engine, check_contract_branch):
                migration.do_alembic_command(
                    self.alembic_config, 'upgrade',
                    '%s@head' % migration.CONTRACT_BRANCH)

    # NOTE(ihrachys): if this test fails for you, it probably means that you
    # attempt to add an unsafe contract migration script, that is in
    # contradiction to blueprint online-upgrades
    def test_forbid_offline_migrations_starting_newton(self):
        engine = self.get_engine()
        cfg.CONF.set_override('connection', engine.url, group='database')
        # the following revisions are Newton heads
        for revision in ('5cd92597d11d', '5c85685d616d'):
            migration.do_alembic_command(
                self.alembic_config, 'upgrade', revision)
        self.assertFalse(migration.has_offline_migrations(
            self.alembic_config, 'unused'),
            msg='Offline contract migration scripts are forbidden for Ocata+')


class TestModelsMigrationsMySQL(testlib_api.MySQLTestCaseMixin,
                                _TestModelsMigrations,
                                testlib_api.SqlTestCaseLight,
                                functional_base.BaseLoggingTestCase):

    def test_check_mysql_engine(self):
        engine = self.get_engine()
        cfg.CONF.set_override('connection', engine.url, group='database')
        with engine.begin() as connection:
            self.alembic_config.attributes['connection'] = connection
            migration.do_alembic_command(self.alembic_config, 'upgrade',
                                         'heads')
            insp = sqlalchemy.inspect(engine)
            # Test that table creation on MySQL only builds InnoDB tables
            tables = insp.get_table_names()
            self.assertGreater(len(tables), 0,
                               "No tables found. Wrong schema?")
            res = [table for table in tables if
                   insp.get_table_options(table)['mysql_engine'] !=
                   'InnoDB' and
                   table != 'alembic_version']
            self.assertEqual(0, len(res), "%s non InnoDB tables created" % res)

    def test_models_sync(self):
        super(TestModelsMigrationsMySQL, self).test_models_sync()


class TestModelsMigrationsPostgreSQL(testlib_api.PostgreSQLTestCaseMixin,
                                     _TestModelsMigrations,
                                     testlib_api.SqlTestCaseLight):
    pass


class TestSanityCheck(testlib_api.SqlTestCaseLight):
    BUILD_SCHEMA = False

    def setUp(self):
        super(TestSanityCheck, self).setUp()
        self.alembic_config = migration.get_neutron_config()
        self.alembic_config.neutron_config = cfg.CONF

    def _drop_table(self, table):
        with self.engine.begin() as conn:
            table.drop(conn)

    def test_check_sanity_1df244e556f5(self):
        ha_router_agent_port_bindings = sqlalchemy.Table(
            'ha_router_agent_port_bindings', sqlalchemy.MetaData(),
            sqlalchemy.Column('port_id', sqlalchemy.String(36)),
            sqlalchemy.Column('router_id', sqlalchemy.String(36)),
            sqlalchemy.Column('l3_agent_id', sqlalchemy.String(36)))

        with self.engine.connect() as conn:
            ha_router_agent_port_bindings.create(conn)
            self.addCleanup(self._drop_table, ha_router_agent_port_bindings)
            # NOTE(haleyb): without this disabled, pylint complains
            # about a missing 'dml' argument.
            # pylint: disable=no-value-for-parameter
            conn.execute(ha_router_agent_port_bindings.insert(), [
                {'port_id': '1234', 'router_id': '12345',
                 'l3_agent_id': '123'},
                {'port_id': '12343', 'router_id': '12345',
                 'l3_agent_id': '123'}
            ])
            script_dir = alembic_script.ScriptDirectory.from_config(
                self.alembic_config)
            script = script_dir.get_revision("1df244e556f5").module
            self.assertRaises(script.DuplicateL3HARouterAgentPortBinding,
                              script.check_sanity, conn)

    def test_check_sanity_030a959ceafa(self):
        routerports = sqlalchemy.Table(
            'routerports', sqlalchemy.MetaData(),
            sqlalchemy.Column('router_id', sqlalchemy.String(36)),
            sqlalchemy.Column('port_id', sqlalchemy.String(36)),
            sqlalchemy.Column('port_type', sqlalchemy.String(255)))

        with self.engine.connect() as conn:
            routerports.create(conn)
            self.addCleanup(self._drop_table, routerports)
            # NOTE(haleyb): without this disabled, pylint complains
            # about a missing 'dml' argument.
            # pylint: disable=no-value-for-parameter
            conn.execute(routerports.insert(), [
                {'router_id': '1234', 'port_id': '12345',
                 'port_type': '123'},
                {'router_id': '12343', 'port_id': '12345',
                 'port_type': '1232'}
            ])
            script_dir = alembic_script.ScriptDirectory.from_config(
                self.alembic_config)
            script = script_dir.get_revision("030a959ceafa").module
            self.assertRaises(script.DuplicatePortRecordinRouterPortdatabase,
                              script.check_sanity, conn)

    def test_check_sanity_6b461a21bcfc_dup_on_fixed_ip(self):
        floatingips = sqlalchemy.Table(
            'floatingips', sqlalchemy.MetaData(),
            sqlalchemy.Column('floating_network_id', sqlalchemy.String(36)),
            sqlalchemy.Column('fixed_port_id', sqlalchemy.String(36)),
            sqlalchemy.Column('fixed_ip_address', sqlalchemy.String(64)))

        with self.engine.connect() as conn:
            floatingips.create(conn)
            self.addCleanup(self._drop_table, floatingips)
            # NOTE(haleyb): without this disabled, pylint complains
            # about a missing 'dml' argument.
            # pylint: disable=no-value-for-parameter
            conn.execute(floatingips.insert(), [
                {'floating_network_id': '12345',
                 'fixed_port_id': '1234567',
                 'fixed_ip_address': '12345678'},
                {'floating_network_id': '12345',
                 'fixed_port_id': '1234567',
                 'fixed_ip_address': '12345678'}
            ])
            script_dir = alembic_script.ScriptDirectory.from_config(
                self.alembic_config)
            script = script_dir.get_revision("6b461a21bcfc").module
            self.assertRaises(script.DuplicateFloatingIPforOneFixedIP,
                              script.check_sanity, conn)

    def test_check_sanity_6b461a21bcfc_dup_on_no_fixed_ip(self):
        floatingips = sqlalchemy.Table(
            'floatingips', sqlalchemy.MetaData(),
            sqlalchemy.Column('floating_network_id', sqlalchemy.String(36)),
            sqlalchemy.Column('fixed_port_id', sqlalchemy.String(36)),
            sqlalchemy.Column('fixed_ip_address', sqlalchemy.String(64)))

        with self.engine.connect() as conn:
            floatingips.create(conn)
            self.addCleanup(self._drop_table, floatingips)
            # NOTE(haleyb): without this disabled, pylint complains
            # about a missing 'dml' argument.
            # pylint: disable=no-value-for-parameter
            conn.execute(floatingips.insert(), [
                {'floating_network_id': '12345',
                 'fixed_port_id': '1234567',
                 'fixed_ip_address': None},
                {'floating_network_id': '12345',
                 'fixed_port_id': '1234567',
                 'fixed_ip_address': None}
            ])
            script_dir = alembic_script.ScriptDirectory.from_config(
                self.alembic_config)
            script = script_dir.get_revision("6b461a21bcfc").module
            self.assertIsNone(script.check_sanity(conn))


class TestWalkDowngrade(oslotest_base.BaseTestCase):

    def setUp(self):
        super(TestWalkDowngrade, self).setUp()
        self.alembic_config = migration.get_neutron_config()
        self.alembic_config.neutron_config = cfg.CONF

    def test_no_downgrade(self):
        script_dir = alembic_script.ScriptDirectory.from_config(
            self.alembic_config)
        versions = [v for v in script_dir.walk_revisions(base='base',
                                                         head='heads')]
        failed_revisions = []
        for version in versions:
            if hasattr(version.module, 'downgrade'):
                failed_revisions.append(version.revision)

        if failed_revisions:
            self.fail('Migrations %s have downgrade' % failed_revisions)
            return True


class _TestWalkMigrations(object):
    '''This will add framework for testing schema migration
       for different backends.

    '''

    BUILD_SCHEMA = False

    def execute_cmd(self, cmd=None):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, shell=True)
        output = proc.communicate()[0]
        self.assertEqual(0, proc.returncode, 'Command failed with '
                         'output:\n%s' % output)

    def _get_alembic_config(self, uri):
        db_config = migration.get_neutron_config()
        self.script_dir = alembic_script.ScriptDirectory.from_config(db_config)
        db_config.neutron_config = cfg.CONF
        db_config.neutron_config.set_override('connection',
                                              str(uri),
                                              group='database')
        return db_config

    def _revisions(self):
        """Provides revisions and its parent revisions.

        :return: List of tuples. Every tuple contains revision and its parent
        revision.
        """
        revisions = list(self.script_dir.walk_revisions("base", "heads"))
        revisions = list(reversed(revisions))

        for rev in revisions:
            # Destination, current
            yield rev.revision, rev.down_revision

    def _migrate_up(self, config, engine, dest, curr):
        data = None
        check = getattr(self, "_check_%s" % dest, None)
        pre_upgrade = getattr(self, "_pre_upgrade_%s" % dest, None)
        if pre_upgrade:
            if curr:
                migration.do_alembic_command(config, 'upgrade', curr)
            data = pre_upgrade(engine)

        if check and data:
            migration.do_alembic_command(config, 'upgrade', dest)
            check(engine, data)

    def test_walk_versions(self):
        """Test migrations ability to upgrade and downgrade.

        """
        engine = self.engine
        config = self._get_alembic_config(engine.url)
        revisions = self._revisions()
        for dest, curr in revisions:
            self._migrate_up(config, engine, dest, curr)

        if dest:
            migration.do_alembic_command(config, 'upgrade', dest)


class TestWalkMigrationsMySQL(testlib_api.MySQLTestCaseMixin,
                              _TestWalkMigrations,
                              testlib_api.SqlTestCaseLight):

    # NOTE(slaweq): this workaround is taken from Manila patch:
    # https://review.opendev.org/#/c/291397/
    # Set 5 minutes timeout for case of running it on
    # very slow nodes/VMs. Note, that this test becomes slower with each
    # addition of new DB migration. On fast nodes it can take about 5-10
    # secs having Mitaka set of migrations. 'pymysql' works much slower
    # on slow nodes than 'psycopg2' and because of that this increased
    # timeout is required only when for testing with 'mysql' backend.
    @test_base.set_timeout(600)
    def test_walk_versions(self):
        super(TestWalkMigrationsMySQL, self).test_walk_versions()


class TestWalkMigrationsPostgreSQL(testlib_api.PostgreSQLTestCaseMixin,
                                   _TestWalkMigrations,
                                   testlib_api.SqlTestCaseLight):
    pass
