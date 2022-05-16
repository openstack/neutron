..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Template for ModelMigrationSync for external repos
==================================================

This section contains a template for a test which checks that the Python models
for database tables are synchronized with the alembic migrations that create
the database schema. This test should be implemented in all driver/plugin
repositories that were split out from Neutron.

What does the test do?
----------------------

This test compares models with the result of existing migrations. It is based on
`ModelsMigrationsSync
<https://docs.openstack.org/oslo.db/latest/reference/api/oslo_db.sqlalchemy.test_migrations.html>`_
which is provided by oslo.db and was adapted for Neutron. It compares core
Neutron models and vendor specific models with migrations from Neutron core and
migrations from the driver/plugin repo. This test is functional - it runs against
MySQL and PostgreSQL dialects. The detailed description of this test can be
found in Neutron Database Layer section - :ref:`testing-database-migrations`.

Steps for implementing the test
-------------------------------

1. Import all models in one place
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a module ``networking_foo/db/models/head.py`` with the following
content: ::

 from neutron_lib.db import model_base

 from networking_foo import models  # noqa
 # Alternatively, import separate modules here if the models are not in one
 # models.py file


 def get_metadata():
    return model_base.BASEV2.metadata


2. Implement the test module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The test uses external.py from Neutron. This file contains lists of table
names, which were moved out of Neutron: ::

 VPNAAS_TABLES = [...]

 FWAAS_TABLES = [...]

 # Arista ML2 driver Models moved to openstack/networking-arista
 REPO_ARISTA_TABLES = [...]

 # Models moved to openstack/networking-cisco
 REPO_CISCO_TABLES = [...]

 ...

 TABLES = (FWAAS_TABLES + VPNAAS_TABLES + ...
           + REPO_ARISTA_TABLES + REPO_CISCO_TABLES)


Also the test uses **VERSION_TABLE**, it is the name of table in database which
contains revision id of head migration. It is preferred to keep this variable in
``networking_foo/db/migration/alembic_migrations/__init__.py`` so it will be easy
to use in test.

Create a module ``networking_foo/tests/functional/db/test_migrations.py``
with the following content: ::

 from oslo_config import cfg

 from neutron.db.migration.alembic_migrations import external
 from neutron.db.migration import cli as migration
 from neutron.tests.functional.db import test_migrations
 from neutron.tests.unit import testlib_api

 from networking_foo.db.migration import alembic_migrations
 from networking_foo.db.models import head

 # EXTERNAL_TABLES should contain all names of tables that are not related to
 # current repo.
 EXTERNAL_TABLES = set(external.TABLES) - set(external.REPO_FOO_TABLES)


 class _TestModelsMigrationsFoo(test_migrations._TestModelsMigrations):

   def db_sync(self, engine):
       cfg.CONF.set_override('connection', engine.url, group='database')
       for conf in migration.get_alembic_configs():
           self.alembic_config = conf
           self.alembic_config.neutron_config = cfg.CONF
           migration.do_alembic_command(conf, 'upgrade', 'heads')

   def get_metadata(self):
       return head.get_metadata()

   def include_object(self, object_, name, type_, reflected, compare_to):
       if type_ == 'table' and (name == 'alembic' or
                                name == alembic_migrations.VERSION_TABLE or
                                name in EXTERNAL_TABLES):
           return False
       else:
           return True


 class TestModelsMigrationsMysql(testlib_api.MySQLTestCaseMixin,
                                 _TestModelsMigrationsFoo,
                                 testlib_api.SqlTestCaseLight):
    pass


 class TestModelsMigrationsPsql(testlib_api.PostgreSQLTestCaseMixin,
                                _TestModelsMigrationsFoo,
                                testlib_api.SqlTestCaseLight):
    pass


3. Add functional requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A separate file ``networking_foo/tests/functional/requirements.txt`` should be
created containing the following requirements that are needed for successful
test execution.

::

 psutil>=3.2.2 # BSD
 psycopg2
 PyMySQL>=0.6.2  # MIT License


Example implementation `in VPNaaS <https://review.opendev.org/209943>`_
