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
import logging
import pprint

import alembic
import alembic.autogenerate
import alembic.migration
import mock
from oslo.config import cfg
from oslo.db.sqlalchemy import test_base
from oslo.db.sqlalchemy import test_migrations
from oslo.db.sqlalchemy import utils
import pkg_resources as pkg
import sqlalchemy
import sqlalchemy.sql.expression as expr
import testscenarios

from neutron.db.migration import cli as migration
from neutron.db.migration.models import head as head_models
from neutron.openstack.common.fixture import config

LOG = logging.getLogger(__name__)


cfg.CONF.import_opt('core_plugin', 'neutron.common.config')
cfg.CONF.import_opt('service_plugins', 'neutron.common.config')


def _discover_plugins(plugin_type):
    return [
        '%s.%s' % (entrypoint.module_name, entrypoint.attrs[0])
        for entrypoint in
        pkg.iter_entry_points(plugin_type)
    ]

SERVICE_PLUGINS = _discover_plugins("neutron.service_plugins")
CORE_PLUGINS = _discover_plugins('neutron.core_plugins')


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
        * what should be modified,
        * schema,
        * table,
        * column,
        * existing correct column parameters,
        * right value,
        * wrong value.

    '''

    def setUp(self):
        patch = mock.patch.dict('sys.modules', {
            'ryu': mock.MagicMock(),
            'ryu.app': mock.MagicMock(),
            'heleosapi': mock.MagicMock(),
            'midonetclient': mock.MagicMock(),
            'midonetclient.neutron': mock.MagicMock(),
        })
        patch.start()
        self.addCleanup(patch.stop)
        super(_TestModelsMigrations, self).setUp()
        self.cfg = self.useFixture(config.Config())
        self.cfg.config(service_plugins=SERVICE_PLUGINS,
                        core_plugin=self.core_plugin)
        self.alembic_config = migration.get_alembic_config()
        self.alembic_config.neutron_config = cfg.CONF

    def db_sync(self, engine):
        cfg.CONF.set_override('connection', engine.url, group='database')
        migration.do_alembic_command(self.alembic_config, 'upgrade', 'head')
        cfg.CONF.clear_override('connection', group='database')

    def get_engine(self):
        return self.engine

    def get_metadata(self):
        return head_models.get_metadata()

    def include_object(self, object_, name, type_, reflected, compare_to):
        if type_ == 'table' and name == 'alembic_version':
                return False

        return super(_TestModelsMigrations, self).include_object(
            object_, name, type_, reflected, compare_to)

    def compare_server_default(self, ctxt, ins_col, meta_col,
                               insp_def, meta_def, rendered_meta_def):
        return self._compare_server_default(ctxt.bind, meta_col, insp_def,
                                            meta_def)

    # TODO(akamyshnikova):remove _compare_server_default methods when it
    # appears in oslo.db(version>1.0.0)
    @utils.DialectFunctionDispatcher.dispatch_for_dialect("*")
    def _compare_server_default(bind, meta_col, insp_def, meta_def):
        pass

    @_compare_server_default.dispatch_for('mysql')
    def _compare_server_default(bind, meta_col, insp_def, meta_def):
        if isinstance(meta_col.type, sqlalchemy.Boolean):
            if meta_def is None or insp_def is None:
                return meta_def != insp_def
            return not (
                isinstance(meta_def.arg, expr.True_) and insp_def == "'1'" or
                isinstance(meta_def.arg, expr.False_) and insp_def == "'0'"
            )

        if isinstance(meta_col.type, sqlalchemy.Integer):
            if meta_def is None or insp_def is None:
                return meta_def != insp_def
            return meta_def.arg == insp_def

    @_compare_server_default.dispatch_for('postgresql')
    def _compare_server_default(bind, meta_col, insp_def, meta_def):
        if isinstance(meta_col.type, sqlalchemy.Enum):
            if meta_def is None or insp_def is None:
                return meta_def != insp_def
            return insp_def != "'%s'::%s" % (meta_def.arg, meta_col.type.name)
        elif isinstance(meta_col.type, sqlalchemy.String):
            if meta_def is None or insp_def is None:
                return meta_def != insp_def
            return insp_def != "'%s'::character varying" % meta_def.arg

    def test_models_sync(self):
        # drop all tables after a test run
        self.addCleanup(self._cleanup)

        # run migration scripts
        self.db_sync(self.get_engine())

        with self.get_engine().connect() as conn:
            opts = {
                'include_object': self.include_object,
                'compare_type': self.compare_type,
                'compare_server_default': self.compare_server_default,
            }
            mc = alembic.migration.MigrationContext.configure(conn, opts=opts)

            # compare schemas and fail with diff, if it's not empty
            diff1 = alembic.autogenerate.compare_metadata(mc,
                                                          self.get_metadata())
            insp = sqlalchemy.engine.reflection.Inspector.from_engine(
                self.get_engine())
            dialect = self.get_engine().dialect.name
            self.check_mysql_engine(dialect, insp)
            diff2 = self.compare_foreign_keys(self.get_metadata(),
                                              self.get_engine())

        result = filter(self.remove_unrelated_errors, diff1 + diff2)
        if result:
            msg = pprint.pformat(result, indent=2, width=20)

            self.fail("Models and migration scripts aren't in sync:\n%s" % msg)

    def check_mysql_engine(self, dialect, insp):
        if dialect != 'mysql':
            return

        # Test that table creation on mysql only builds InnoDB tables
        tables = insp.get_table_names()
        self.assertTrue(len(tables) > 0,
                        "No tables found. Wrong schema?")
        noninnodb = [table for table in tables if
                     insp.get_table_options(table)['mysql_engine'] != 'InnoDB'
                     and table != 'alembic_version']
        self.assertEqual(0, len(noninnodb), "%s non InnoDB tables created" %
                                            noninnodb)

    FKInfo = collections.namedtuple('FKInfo', ['constrained_columns',
                                               'referred_table',
                                               'referred_columns'])

    def compare_foreign_keys(self, metadata, bind):
        """Compare foreign keys between model and db table.

        Returns a list that contains information about:
         * should be a new key added or removed existing,
         * name of that key,
         * source table,
         * referred table,
         * constrained columns,
         * referred columns

         Output::

             [('drop_key',
               'testtbl_fk_check_fkey',
               'testtbl',
               fk_info(constrained_columns=(u'fk_check',),
                       referred_table=u'table',
                       referred_columns=(u'fk_check',)))]

        """

        diff = []
        insp = sqlalchemy.engine.reflection.Inspector.from_engine(bind)
        # Get all tables from db
        db_tables = insp.get_table_names()
        # Get all tables from models
        model_tables = metadata.tables
        for table in db_tables:
            if table not in model_tables:
                continue
            # Get all necessary information about key of current table from db
            fk_db = dict((self._get_fk_info_from_db(i), i['name'])
                         for i in insp.get_foreign_keys(table))
            fk_db_set = set(fk_db.keys())
            # Get all necessary information about key of current table from
            # models
            fk_models = dict((self._get_fk_info_from_model(fk), fk)
                             for fk in model_tables[table].foreign_keys)
            fk_models_set = set(fk_models.keys())
            for key in (fk_db_set - fk_models_set):
                diff.append(('drop_key', fk_db[key], table, key))
                LOG.info(("Detected removed foreign key %(fk)r on "
                          "table %(table)r"), {'fk': fk_db[key],
                                               'table': table})
            for key in (fk_models_set - fk_db_set):
                diff.append(('add_key', fk_models[key], key))
                LOG.info((
                    "Detected added foreign key for column %(fk)r on table "
                    "%(table)r"), {'fk': fk_models[key].column.name,
                                   'table': table})
        return diff

    def _get_fk_info_from_db(self, fk):
        return self.FKInfo(tuple(fk['constrained_columns']),
                           fk['referred_table'],
                           tuple(fk['referred_columns']))

    def _get_fk_info_from_model(self, fk):
        return self.FKInfo((fk.parent.name,), fk.column.table.name,
                           (fk.column.name,))

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

load_tests = testscenarios.load_tests_apply_scenarios

_scenarios = []
for plugin in CORE_PLUGINS:
    plugin_name = plugin.split('.')[-1]
    class_name = plugin_name
    _scenarios.append((class_name, {'core_plugin': plugin}))


class TestModelsMigrationsMysql(_TestModelsMigrations,
                                test_base.MySQLOpportunisticTestCase):
    scenarios = _scenarios


class TestModelsMigrationsPsql(_TestModelsMigrations,
                               test_base.PostgreSQLOpportunisticTestCase):
    scenarios = _scenarios
