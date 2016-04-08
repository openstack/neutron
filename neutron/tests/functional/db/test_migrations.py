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
import abc
from alembic import script as alembic_script
from contextlib import contextmanager
import os
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_db.sqlalchemy import session
from oslo_db.sqlalchemy import test_base
from oslo_db.sqlalchemy import test_migrations
from oslo_db.sqlalchemy import utils as oslo_utils
from oslo_log import log as logging
import six
from six.moves import configparser
from six.moves.urllib import parse
import sqlalchemy
from sqlalchemy import event
import sqlalchemy.types as types
import subprocess

import neutron.db.migration as migration_help
from neutron.db.migration.alembic_migrations import external
from neutron.db.migration import cli as migration
from neutron.db.migration.models import head as head_models
from neutron.tests import base as base_tests
from neutron.tests.common import base

LOG = logging.getLogger(__name__)

cfg.CONF.import_opt('core_plugin', 'neutron.common.config')

CORE_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'


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
    '''

    def setUp(self):
        super(_TestModelsMigrations, self).setUp()
        self.cfg = self.useFixture(config_fixture.Config())
        self.cfg.config(core_plugin=CORE_PLUGIN)
        self.alembic_config = migration.get_neutron_config()
        self.alembic_config.neutron_config = cfg.CONF

    def db_sync(self, engine):
        cfg.CONF.set_override('connection', engine.url, group='database')
        migration.do_alembic_command(self.alembic_config, 'upgrade', 'heads')

    def get_engine(self):
        return self.engine

    def get_metadata(self):
        return head_models.get_metadata()

    def include_object(self, object_, name, type_, reflected, compare_to):
        if type_ == 'table' and (name == 'alembic_version'
                                 or name in external.TABLES):
                return False

        return super(_TestModelsMigrations, self).include_object(
            object_, name, type_, reflected, compare_to)

    def filter_metadata_diff(self, diff):
        return list(filter(self.remove_unrelated_errors, diff))

    # TODO(akamyshikova): remove this method as soon as comparison with Variant
    # will be implemented in oslo.db or alembic
    def compare_type(self, ctxt, insp_col, meta_col, insp_type, meta_type):
        if isinstance(meta_type, types.Variant):
            orig_type = meta_col.type
            meta_col.type = meta_type.impl
            try:
                return self.compare_type(ctxt, insp_col, meta_col, insp_type,
                                         meta_type.impl)
            finally:
                meta_col.type = orig_type
        else:
            ret = super(_TestModelsMigrations, self).compare_type(
                ctxt, insp_col, meta_col, insp_type, meta_type)
            if ret is not None:
                return ret
            return ctxt.impl.compare_type(insp_col, meta_col)

    # Remove some difference that are not mistakes just specific of
    # dialects, etc
    def remove_unrelated_errors(self, element):
        insp = sqlalchemy.engine.reflection.Inspector.from_engine(
            self.get_engine())
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


class TestModelsMigrationsMysql(_TestModelsMigrations,
                                base.MySQLTestCase):
    @contextmanager
    def _listener(self, engine, listener_func):
        try:
            event.listen(engine, 'before_execute', listener_func)
            yield
        finally:
            event.remove(engine, 'before_execute',
                         listener_func)

    # There is no use to run this against both dialects, so add this test just
    # for MySQL tests
    def test_external_tables_not_changed(self):

        def block_external_tables(conn, clauseelement, multiparams, params):
            if isinstance(clauseelement, sqlalchemy.sql.selectable.Select):
                return

            if (isinstance(clauseelement, six.string_types) and
                    any(name in clauseelement for name in external.TABLES)):
                self.fail("External table referenced by neutron core "
                          "migration.")

            if hasattr(clauseelement, 'element'):
                element = clauseelement.element
                if (element.name in external.TABLES or
                        (hasattr(clauseelement, 'table') and
                            element.table.name in external.TABLES)):
                    # Table 'nsxv_vdr_dhcp_bindings' was created in liberty,
                    # before NSXV has moved to separate repo.
                    if ((isinstance(clauseelement,
                                    sqlalchemy.sql.ddl.CreateTable) and
                            element.name == 'nsxv_vdr_dhcp_bindings')):
                        return
                    self.fail("External table referenced by neutron core "
                              "migration.")

        engine = self.get_engine()
        cfg.CONF.set_override('connection', engine.url, group='database')
        with engine.begin() as connection:
            self.alembic_config.attributes['connection'] = connection
            migration.do_alembic_command(self.alembic_config, 'upgrade',
                                         'kilo')

            with self._listener(engine,
                                block_external_tables):
                migration.do_alembic_command(self.alembic_config, 'upgrade',
                                             'heads')

    def test_branches(self):

        def check_expand_branch(conn, clauseelement, multiparams, params):
            if isinstance(clauseelement, migration_help.DROP_OPERATIONS):
                self.fail("Migration from expand branch contains drop command")

        def check_contract_branch(conn, clauseelement, multiparams, params):
            if isinstance(clauseelement, migration_help.CREATION_OPERATIONS):
                # Skip tables that were created by mistake in contract branch
                if hasattr(clauseelement, 'element'):
                    element = clauseelement.element
                    if any([
                        isinstance(element, sqlalchemy.Table) and
                        element.name in ['ml2_geneve_allocations',
                                         'ml2_geneve_endpoints'],
                        isinstance(element, sqlalchemy.Index) and
                        element.table.name == 'ml2_geneve_allocations'
                    ]):
                        return
                self.fail("Migration from contract branch contains create "
                          "command")

        engine = self.get_engine()
        cfg.CONF.set_override('connection', engine.url, group='database')
        with engine.begin() as connection:
            self.alembic_config.attributes['connection'] = connection
            migration.do_alembic_command(self.alembic_config, 'upgrade',
                                         'kilo')

            with self._listener(engine, check_expand_branch):
                migration.do_alembic_command(
                    self.alembic_config, 'upgrade',
                    '%s@head' % migration.EXPAND_BRANCH)

            with self._listener(engine, check_contract_branch):
                migration.do_alembic_command(
                    self.alembic_config, 'upgrade',
                    '%s@head' % migration.CONTRACT_BRANCH)

    def test_check_mysql_engine(self):
        engine = self.get_engine()
        cfg.CONF.set_override('connection', engine.url, group='database')
        with engine.begin() as connection:
            self.alembic_config.attributes['connection'] = connection
            migration.do_alembic_command(self.alembic_config, 'upgrade',
                                         'heads')
            insp = sqlalchemy.engine.reflection.Inspector.from_engine(engine)
            # Test that table creation on MySQL only builds InnoDB tables
            tables = insp.get_table_names()
            self.assertTrue(len(tables) > 0,
                            "No tables found. Wrong schema?")
            res = [table for table in tables if
                   insp.get_table_options(table)['mysql_engine'] != 'InnoDB'
                   and table != 'alembic_version']
            self.assertEqual(0, len(res), "%s non InnoDB tables created" % res)

    def _test_has_offline_migrations(self, revision, expected):
        engine = self.get_engine()
        cfg.CONF.set_override('connection', engine.url, group='database')
        migration.do_alembic_command(self.alembic_config, 'upgrade', revision)
        self.assertEqual(expected,
                         migration.has_offline_migrations(self.alembic_config,
                                                          'unused'))

    def test_has_offline_migrations_pending_contract_scripts(self):
        self._test_has_offline_migrations('kilo', True)

    def test_has_offline_migrations_all_heads_upgraded(self):
        self._test_has_offline_migrations('heads', False)


class TestModelsMigrationsPsql(_TestModelsMigrations,
                               base.PostgreSQLTestCase):
    pass


class TestSanityCheck(test_base.DbTestCase):

    def setUp(self):
        super(TestSanityCheck, self).setUp()
        self.alembic_config = migration.get_neutron_config()
        self.alembic_config.neutron_config = cfg.CONF

    def test_check_sanity_1df244e556f5(self):
        ha_router_agent_port_bindings = sqlalchemy.Table(
            'ha_router_agent_port_bindings', sqlalchemy.MetaData(),
            sqlalchemy.Column('port_id', sqlalchemy.String(36)),
            sqlalchemy.Column('router_id', sqlalchemy.String(36)),
            sqlalchemy.Column('l3_agent_id', sqlalchemy.String(36)))

        with self.engine.connect() as conn:
            ha_router_agent_port_bindings.create(conn)
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


class TestWalkDowngrade(test_base.DbTestCase):

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


def _is_backend_avail(backend,
                      user="openstack_citest",
                      passwd="openstack_citest",
                      database="openstack_citest"):
    # is_backend_avail will be soon deprecated from oslo_db
    # thats why its added here
    try:
        connect_uri = oslo_utils.get_connect_string(backend, user=user,
                                                    passwd=passwd,
                                                    database=database)
        engine = session.create_engine(connect_uri)
        connection = engine.connect()
    except Exception as e:
        # intentionally catch all to handle exceptions even if we don't
        # have any backend code loaded.
        LOG.critical('Backend %s failed: %s' % (backend, e))
        return False
    else:
        connection.close()
        engine.dispose()
        return True


def execute_cmd(cmd=None):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, shell=True)
    output = proc.communicate()[0]
    assert(proc.returncode == 0), 'Command failed with output:\n%s' % output


@six.add_metaclass(abc.ABCMeta)
class _TestWalkMigrations(base_tests.BaseTestCase):
    '''This will add framework for testing schema migarations
       for different backends.

    Right now it supports pymysql and postgresql backends. Pymysql
    and postgresql commands are executed to walk between to do updates.
    For upgrade and downgrade migrate_up and migrate down functions
    have been added.
    '''

    DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(__file__),
                                       'test_migrations.conf')
    CONFIG_FILE_PATH = os.environ.get('NEUTRON_TEST_MIGRATIONS_CONF',
                                      DEFAULT_CONFIG_FILE)

    def setUp(self):
        if not _is_backend_avail(self.BACKEND):
            self.skipTest("%s not available" % self.BACKEND)

        super(_TestWalkMigrations, self).setUp()

        self.snake_walk = False
        self.test_databases = {}

        if os.path.exists(self.CONFIG_FILE_PATH):
            cp = configparser.RawConfigParser()
            try:
                cp.read(self.CONFIG_FILE_PATH)
                options = cp.options('migration_dbs')
                for key in options:
                    self.test_databases[key] = cp.get('migration_dbs', key)
                self.snake_walk = cp.getboolean('walk_style', 'snake_walk')
            except configparser.ParsingError as e:
                self.fail("Failed to read test_migrations.conf config "
                          "file. Got error: %s" % e)
        else:
            self.fail("Failed to find test_migrations.conf config "
                      "file.")

        self.engines = {}
        for key, value in self.test_databases.items():
            self.engines[key] = sqlalchemy.create_engine(value)

            # We start each test case with a completely blank slate.
            self._reset_databases(key)

    def assertColumnInTable(self, engine, table_name, column):
        table = oslo_utils.get_table(engine, table_name)
        self.assertIn(column, table.columns)

    def assertColumnNotInTables(self, engine, table_name, column):
        table = oslo_utils.get_table(engine, table_name)
        self.assertNotIn(column, table.columns)

    @abc.abstractproperty
    def BACKEND(self):
        pass

    @abc.abstractmethod
    def _database_recreate(self, user, password, database, host):
        pass

    def _reset_databases(self, key):
        # for key, engine in self.engines.items():
        if key not in self.test_databases:
            LOG.critical('%s not in self.test_databases' % key)
            LOG.critical('self.test_databases keys: '
                         '%s' % self.test_databases.keys())
            key = "%s%s" % (key.split('+')[0], "citest")
            LOG.critical('Trying %s instead' % key)

        conn_string = self.test_databases[key]
        conn_pieces = parse.urlparse(conn_string)
        user, password, database, host = oslo_utils.get_db_connection_info(
            conn_pieces)
        self.engines[key].dispose()
        self._database_recreate(user, password, database, host)

    def _get_alembic_config(self, uri):
        db_config = migration.get_neutron_config()
        self.script_dir = alembic_script.ScriptDirectory.from_config(db_config)
        db_config.neutron_config = cfg.CONF
        db_config.neutron_config.set_override('connection',
                                              six.text_type(uri),
                                              group='database')
        return db_config

    def _revisions(self, downgrade=False):
        """Provides revisions and its parent revisions.

        :param downgrade: whether to include downgrade behavior or not.
        :type downgrade: Bool
        :return: List of tuples. Every tuple contains revision and its parent
        revision.
        """
        revisions = list(self.script_dir.walk_revisions("base", "heads"))
        if not downgrade:
            revisions = list(reversed(revisions))

        for rev in revisions:
            if downgrade:
                # Destination, current
                yield rev.down_revision, rev.revision
            else:
                # Destination, current
                yield rev.revision, rev.down_revision

    def _walk_versions(self, config, engine, downgrade=True, snake_walk=False):
        """Test migrations ability to upgrade and downgrade.

        :param downgrade: whether to include downgrade behavior or not.
        :type downgrade: Bool
        :snake_walk: enable mode when at every upgrade revision will be
        downgraded and upgraded in previous state at upgrade and backward at
        downgrade.
        :type snake_walk: Bool
        """
        revisions = self._revisions()
        for dest, curr in revisions:
            self._migrate_up(config, engine, dest, curr, with_data=True)

            if snake_walk and dest != 'None':
                # NOTE(I159): Pass reversed arguments into `_migrate_down`
                # method because we have been upgraded to a destination
                # revision and now we going to downgrade back.
                self._migrate_down(config, engine, curr, dest, with_data=True)
                self._migrate_up(config, engine, dest, curr, with_data=True)

        if downgrade:
            revisions = self._revisions(downgrade)
            for dest, curr in revisions:
                self._migrate_down(config, engine, dest, curr, with_data=True)
                if snake_walk:
                    self._migrate_up(config, engine, curr,
                                     dest, with_data=True)
                    self._migrate_down(config, engine, dest,
                                       curr, with_data=True)

    def _migrate_down(self, config, engine, dest, curr, with_data=False):
        if dest:
            migration.do_alembic_command(config, 'downgrade', dest)
        else:
            meta = sqlalchemy.MetaData(bind=engine)
            meta.drop_all()

        if with_data:
            post_downgrade = getattr(
                self, "_post_downgrade_%s" % curr, None)
            if post_downgrade:
                post_downgrade(engine)

    def _migrate_up(self, config, engine, dest, curr, with_data=False):
        if with_data:
            data = None
            pre_upgrade = getattr(
                self, "_pre_upgrade_%s" % dest, None)
            if pre_upgrade:
                data = pre_upgrade(engine)
        migration.do_alembic_command(config, 'upgrade', dest)
        if with_data:
            check = getattr(self, "_check_%s" % dest, None)
            if check and data:
                check(engine, data)


class DatabaseRecreator(object):
    @classmethod
    def mysql(self, user, password, database, host):
        # We can execute the MySQL client to destroy and re-create
        # the MYSQL database, which is easier and less error-prone
        # than using SQLAlchemy to do this via MetaData...trust me.
        sql = ("drop database if exists %(database)s; create "
               "database %(database)s;") % {'database': database}
        cmd = ("mysql -u \"%(user)s\" -p%(password)s -h %(host)s "
               "-e \"%(sql)s\"") % {'user': user, 'password': password,
                                    'host': host, 'sql': sql}
        execute_cmd(cmd)

    @classmethod
    def psql(self, user, password, database, host):
        os.environ['PGPASSWORD'] = password
        os.environ['PGUSER'] = user
        # note(boris-42): We must create and drop database, we can't
        # drop database which we have connected to, so for such
        # operations there is a special database template1.
        sqlcmd = ("psql -w -U %(user)s -h %(host)s -c"
                  " '%(sql)s' -d template1")
        sql = "drop database if exists %(database)s;"
        sql = sql % {'database': database}
        droptable = sqlcmd % {'user': user, 'host': host,
                              'sql': sql}
        execute_cmd(droptable)
        sql = "create database %(database)s;"
        sql = sql % {'database': database}
        createtable = sqlcmd % {'user': user, 'host': host,
                                'sql': sql}
        execute_cmd(createtable)


class TestWalkMigrationsMysql(_TestWalkMigrations):

    BACKEND = 'mysql+pymysql'

    def _database_recreate(self, user, password, database, host):
        DatabaseRecreator.mysql(user, password, database, host)

    def test_mysql_opportunistically(self):
        connect_string = oslo_utils.get_connect_string(self.BACKEND,
            "openstack_citest", user="openstack_citest",
            passwd="openstack_citest")
        engine = engine = session.create_engine(connect_string)
        config = self._get_alembic_config(connect_string)
        self.engines["mysqlcitest"] = engine
        self.test_databases["mysqlcitest"] = connect_string

        # build a fully populated mysql database with all the tables
        self._reset_databases("mysqlcitest")
        self._walk_versions(config, engine, False, False)

    # def _test_mysql_revise(self, dest, curr):
    #     connect_string = oslo_utils.get_connect_string(self.BACKEND,
    #         "openstack_citest", user="openstack_citest",
    #         passwd="openstack_citest")
    #     engine = session.create_engine(connect_string)
    #     config = self._get_alembic_config(connect_string)
    #     self.engines["mysqlcitest"] = engine
    #     self.test_databases["mysqlcitest"] = connect_string
    #     self._reset_databases()
    #     self._migrate_up(config, engine, dest=curr, curr=None)
    #     self._migrate_up(config, engine, dest=dest, curr=curr,
    #                      with_data=True)

    def _test_mysql_revise(self, dest, curr, BACKENDS=['mysql+pymysql',
                                                       'postgresql']):
        for backend in BACKENDS:
            connect_string = oslo_utils.get_connect_string(backend,
                "openstack_citest", user="openstack_citest",
                passwd="openstack_citest")
            engine = session.create_engine(connect_string)
            config = self._get_alembic_config(connect_string)
            engine_name = "%s%s" % (backend.split('+')[0], 'citest')
            LOG.critical('Resetting %s' % engine_name)
            if engine_name not in self.engines:
                self.engines.update({engine_name: engine})
            else:
                self.engines[engine_name] = engine
            if engine_name not in self.test_databases:
                self.test_databases.update({engine_name: connect_string})
            else:
                self.test_databases[engine_name] = connect_string
            self._reset_databases(backend)
            LOG.critical('Reset complete, migrating...')
            self._migrate_up(config, engine, dest=curr, curr=None)
            self._migrate_up(config, engine, dest=dest, curr=curr,
                             with_data=True)

    def _pre_upgrade_c3a73f615e4(self, engine):
        address_scopes = oslo_utils.get_table(engine, 'address_scopes')
        return address_scopes.columns

    def _check_c3a73f615e4(self, engine, pre_upgrade_columns):
        self.assertNotIn('ip_version', pre_upgrade_columns)
        self.assertColumnInTable(engine, 'address_scopes', 'ip_version')

    def test_revise_dce3ec7a25c9_to_c3a73f615e4(self):
        self._test_mysql_revise(dest='c3a73f615e4', curr='dce3ec7a25c9')


class TestWalkMigrationsPsql(_TestWalkMigrations):

    BACKEND = 'postgresql'

    def _database_recreate(self, user, password, database, host):
        DatabaseRecreator.psql(user, password, database, host)

    def test_postgresql_opportunistically(self):
        # add this to the global lists to make reset work with it, it's removed
        # automatically in tearDown so no need to clean it up here.
        connect_string = oslo_utils.get_connect_string(self.BACKEND,
                                                       "openstack_citest",
                                                       "openstack_citest",
                                                       "openstack_citest")
        engine = session.create_engine(connect_string)
        config = self._get_alembic_config(connect_string)
        self.engines["postgresqlcitest"] = engine
        self.test_databases["postgresqlcitest"] = connect_string

        # build a fully populated postgresql database with all the tables
        self._reset_databases("postgresql")
        self._walk_versions(config, engine, False, False)
