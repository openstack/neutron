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

from alembic import script as alembic_script
from contextlib import contextmanager
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_db.sqlalchemy import test_base
from oslo_db.sqlalchemy import test_migrations
import six
import sqlalchemy
from sqlalchemy import event
import sqlalchemy.types as types

import neutron.db.migration as migration_help
from neutron.db.migration.alembic_migrations import external
from neutron.db.migration import cli as migration
from neutron.db.migration.models import head as head_models
from neutron.tests.common import base

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


class TestWalkMigrations(test_base.DbTestCase):

    def setUp(self):
        super(TestWalkMigrations, self).setUp()
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
