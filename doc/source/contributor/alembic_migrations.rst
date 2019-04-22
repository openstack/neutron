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

.. _alembic_migrations:

Alembic Migrations
==================

Introduction
------------

The migrations in the alembic/versions contain the changes needed to migrate
from older Neutron releases to newer versions. A migration occurs by executing
a script that details the changes needed to upgrade the database. The migration
scripts are ordered so that multiple scripts can run sequentially to update the
database.


The Migration Wrapper
---------------------

The scripts are executed by Neutron's migration wrapper ``neutron-db-manage``
which uses the Alembic library to manage the migration. Pass the ``--help``
option to the wrapper for usage information.

The wrapper takes some options followed by some commands::

 neutron-db-manage <options> <commands>

The wrapper needs to be provided with the database connection string, which is
usually provided in the ``neutron.conf`` configuration file in an installation.
The wrapper automatically reads from ``/etc/neutron/neutron.conf`` if it is
present. If the configuration is in a different location::

 neutron-db-manage --config-file /path/to/neutron.conf <commands>

Multiple ``--config-file`` options can be passed if needed.

Instead of reading the DB connection from the configuration file(s) the
``--database-connection`` option can be used::

 neutron-db-manage --database-connection mysql+pymysql://root:secret@127.0.0.1/neutron?charset=utf8 <commands>

The ``branches``, ``current``, and ``history`` commands all accept a
``--verbose`` option, which, when passed, will instruct ``neutron-db-manage``
to display more verbose output for the specified command::

 neutron-db-manage current --verbose

For some commands the wrapper needs to know the entrypoint of the core plugin
for the installation. This can be read from the configuration file(s) or
specified using the ``--core_plugin`` option::

 neutron-db-manage --core_plugin neutron.plugins.ml2.plugin.Ml2Plugin <commands>

When giving examples below of using the wrapper the options will not be shown.
It is assumed you will use the options that you need for your environment.

For new deployments you will start with an empty database. You then upgrade
to the latest database version via::

 neutron-db-manage upgrade heads

For existing deployments the database will already be at some version. To
check the current database version::

 neutron-db-manage current

After installing a new version of Neutron server, upgrading the database is
the same command::

 neutron-db-manage upgrade heads

To create a script to run the migration offline::

 neutron-db-manage upgrade heads --sql

To run the offline migration between specific migration versions::

 neutron-db-manage upgrade <start version>:<end version> --sql

Upgrade the database incrementally::

 neutron-db-manage upgrade --delta <# of revs>

**NOTE:** Database downgrade is not supported.


Migration Branches
------------------

Neutron makes use of alembic branches for two purposes.

1. Independent Sub-Project Tables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Various `Sub-Projects <../contributor/stadium/guidelines.html>`_ can be installed with Neutron. Each
sub-project registers its own alembic branch which is responsible for migrating
the schemas of the tables owned by the sub-project.

The neutron-db-manage script detects which sub-projects have been installed by
enumerating the ``neutron.db.alembic_migrations`` entrypoints. For more details
see the `Entry Points section of Contributing extensions to Neutron
<contribute.html#entry-points>`_.

The neutron-db-manage script runs the given alembic command against all
installed sub-projects. (An exception is the ``revision`` command, which is
discussed in the `Developers`_ section below.)

2. Offline/Online Migrations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since Liberty, Neutron maintains two parallel alembic migration branches.

The first one, called 'expand', is used to store expansion-only migration
rules. Those rules are strictly additive and can be applied while
neutron-server is running. Examples of additive database schema changes are:
creating a new table, adding a new table column, adding a new index, etc.

The second branch, called 'contract', is used to store those migration rules
that are not safe to apply while neutron-server is running. Those include:
column or table removal, moving data from one part of the database into another
(renaming a column, transforming single table into multiple, etc.), introducing
or modifying constraints, etc.

The intent of the split is to allow invoking those safe migrations from
'expand' branch while neutron-server is running, reducing downtime needed to
upgrade the service.

For more details, see the `Expand and Contract Scripts`_ section below.


Developers
----------

A database migration script is required when you submit a change to Neutron or
a sub-project that alters the database model definition. The migration script
is a special python file that includes code to upgrade the database to match
the changes in the model definition. Alembic will execute these scripts in
order to provide a linear migration path between revisions. The
neutron-db-manage command can be used to generate migration scripts for you to
complete. The operations in the template are those supported by the Alembic
migration library.


.. _neutron-db-manage-without-devstack:

Running neutron-db-manage without devstack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When, as a developer, you want to work with the Neutron DB schema and alembic
migrations only, it can be rather tedious to rely on devstack just to get an
up-to-date neutron-db-manage installed. This section describes how to work on
the schema and migration scripts with just the unit test virtualenv and
mysql. You can also operate on a separate test database so you don't mess up
the installed Neutron database.

Setting up the environment
++++++++++++++++++++++++++

Install mysql service
'''''''''''''''''''''

This only needs to be done once since it is a system install. If you have run
devstack on your system before, then the mysql service is already installed and
you can skip this step.

Mysql must be configured as installed by devstack, and the following script
accomplishes this without actually running devstack::

 INSTALL_MYSQL_ONLY=True ./tools/configure_for_func_testing.sh ../devstack

Run this from the root of the neutron repo. It assumes an up-to-date clone of
the devstack repo is in ``../devstack``.

Note that you must know the mysql root password. It is derived from (in order
of precedence):

- ``$MYSQL_PASSWORD`` in your environment
- ``$MYSQL_PASSWORD`` in ``../devstack/local.conf``
- ``$MYSQL_PASSWORD`` in ``../devstack/localrc``
- default of 'secretmysql' from ``tools/configure_for_func_testing.sh``

Work on a test database
'''''''''''''''''''''''

Rather than using the neutron database when working on schema and alembic
migration script changes, we can work on a test database. In the examples
below, we use a database named ``testdb``.

To create the database::

 mysql -e "create database testdb;"

You will often need to clear it to re-run operations from a blank database::

 mysql -e "drop database testdb; create database testdb;"

To work on the test database instead of the neutron database, point to it with
the ``--database-connection`` option::

 neutron-db-manage --database-connection mysql+pymysql://root:secretmysql@127.0.0.1/testdb?charset=utf8 <commands>

You may find it convenient to set up an alias (in your .bashrc) for this::

 alias test-db-manage='neutron-db-manage --database-connection mysql+pymysql://root:secretmysql@127.0.0.1/testdb?charset=utf8'

Create and activate the virtualenv
''''''''''''''''''''''''''''''''''

From the root of the neutron (or sub-project) repo directory, run::

 tox --notest -r -e py27
 source .tox/py27/bin/activate

Now you can use the ``test-db-manage`` alias in place of ``neutron-db-manage``
in the script auto-generation instructions below.

When you are done, exit the virtualenv::

 deactivate


Script Auto-generation
~~~~~~~~~~~~~~~~~~~~~~

This section describes how to auto-generate an alembic migration script for a
model change. You may either use the system installed devstack environment, or
a virtualenv + testdb environment as described in
:ref:`neutron-db-manage-without-devstack`.

Stop the neutron service. Work from the base directory of the neutron (or
sub-project) repo. Check out the master branch and do ``git pull`` to
ensure it is fully up to date. Check out your development branch and rebase to
master.

**NOTE:** Make sure you have not updated the ``CONTRACT_HEAD`` or
``EXPAND_HEAD`` yet at this point.

Start with an empty database and upgrade to heads::

 mysql -e "drop database neutron; create database neutron;"
 neutron-db-manage upgrade heads

The database schema is now created without your model changes. The alembic
``revision --autogenerate`` command will look for differences between the
schema generated by the upgrade command and the schema defined by the models,
including your model updates::

 neutron-db-manage revision -m "description of revision" --autogenerate

This generates a prepopulated template with the changes needed to match the
database state with the models.  You should inspect the autogenerated template
to ensure that the proper models have been altered.
When running the above command you will probably get the following error
message::

  Multiple heads are present; please specify the head revision on which the
  new revision should be based, or perform a merge.

This is alembic telling you that it does not know which branch (contract or
expand) to generate the revision for. You must decide, based on whether you
are doing contracting or expanding changes to the schema, and provide either
the ``--contract`` or ``--expand`` option. If you have both types of changes,
you must run the command twice, once with each option, and then manually edit
the generated revision scripts to separate the migration operations.

In rare circumstances, you may want to start with an empty migration template
and manually author the changes necessary for an upgrade.  You can create a
blank file for a branch via::

 neutron-db-manage revision -m "description of revision" --expand
 neutron-db-manage revision -m "description of revision" --contract

**NOTE:** If you use above command you should check that migration is created
in a directory that is named as current release. If not, please raise the issue
with the development team (IRC, mailing list, launchpad bug).

**NOTE:** The "description of revision" text should be a simple English
sentence. The first 30 characters of the description will be used in the file
name for the script, with underscores substituted for spaces. If the truncation
occurs at an awkward point in the description, you can modify the script file
name manually before committing.

The timeline on each alembic branch should remain linear and not interleave
with other branches, so that there is a clear path when upgrading. To verify
that alembic branches maintain linear timelines, you can run this command::

 neutron-db-manage check_migration

If this command reports an error, you can troubleshoot by showing the migration
timelines using the ``history`` command::

 neutron-db-manage history


Expand and Contract Scripts
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The obsolete "branchless" design of a migration script included that it
indicates a specific "version" of the schema, and includes directives that
apply all necessary changes to the database at once.  If we look for example at
the script ``2d2a8a565438_hierarchical_binding.py``, we will see::

    # .../alembic_migrations/versions/2d2a8a565438_hierarchical_binding.py

    def upgrade():

        # .. inspection code ...

        op.create_table(
            'ml2_port_binding_levels',
            sa.Column('port_id', sa.String(length=36), nullable=False),
            sa.Column('host', sa.String(length=255), nullable=False),
            # ... more columns ...
        )

        for table in port_binding_tables:
            op.execute((
                "INSERT INTO ml2_port_binding_levels "
                "SELECT port_id, host, 0 AS level, driver, segment AS segment_id "
                "FROM %s "
                "WHERE host <> '' "
                "AND driver <> '';"
            ) % table)

        op.drop_constraint(fk_name_dvr[0], 'ml2_dvr_port_bindings', 'foreignkey')
        op.drop_column('ml2_dvr_port_bindings', 'cap_port_filter')
        op.drop_column('ml2_dvr_port_bindings', 'segment')
        op.drop_column('ml2_dvr_port_bindings', 'driver')

        # ... more DROP instructions ...

The above script contains directives that are both under the "expand"
and "contract" categories, as well as some data migrations.  the ``op.create_table``
directive is an "expand"; it may be run safely while the old version of the
application still runs, as the old code simply doesn't look for this table.
The ``op.drop_constraint`` and ``op.drop_column`` directives are
"contract" directives (the drop column more so than the drop constraint); running
at least the ``op.drop_column`` directives means that the old version of the
application will fail, as it will attempt to access these columns which no longer
exist.

The data migrations in this script are adding new
rows to the newly added ``ml2_port_binding_levels`` table.

Under the new migration script directory structure, the above script would be
stated as two scripts; an "expand" and a "contract" script::

    # expansion operations
    # .../alembic_migrations/versions/liberty/expand/2bde560fc638_hierarchical_binding.py

    def upgrade():

        op.create_table(
            'ml2_port_binding_levels',
            sa.Column('port_id', sa.String(length=36), nullable=False),
            sa.Column('host', sa.String(length=255), nullable=False),
            # ... more columns ...
        )


    # contraction operations
    # .../alembic_migrations/versions/liberty/contract/4405aedc050e_hierarchical_binding.py

    def upgrade():

        for table in port_binding_tables:
            op.execute((
                "INSERT INTO ml2_port_binding_levels "
                "SELECT port_id, host, 0 AS level, driver, segment AS segment_id "
                "FROM %s "
                "WHERE host <> '' "
                "AND driver <> '';"
            ) % table)

        op.drop_constraint(fk_name_dvr[0], 'ml2_dvr_port_bindings', 'foreignkey')
        op.drop_column('ml2_dvr_port_bindings', 'cap_port_filter')
        op.drop_column('ml2_dvr_port_bindings', 'segment')
        op.drop_column('ml2_dvr_port_bindings', 'driver')

        # ... more DROP instructions ...

The two scripts would be present in different subdirectories and also part of
entirely separate versioning streams.  The "expand" operations are in the
"expand" script, and the "contract" operations are in the "contract" script.

For the time being, data migration rules also belong to contract branch. There
is expectation that eventually live data migrations move into middleware that
will be aware about different database schema elements to converge on, but
Neutron is still not there.

Scripts that contain only expansion or contraction rules do not require a split
into two parts.

If a contraction script depends on a script from expansion stream, the
following directive should be added in the contraction script::

    depends_on = ('<expansion-revision>',)

Expand and Contract Branch Exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In some cases, we have to have "expand" operations in contract migrations. For
example, table 'networksegments' was renamed in contract migration, so all
operations with this table are required to be in contract branch as well.
For such cases, we use the ``contract_creation_exceptions`` that should be
implemented as part of such migrations. This is needed to get functional tests
pass.

Usage::

    def contract_creation_exceptions():
        """Docstring should explain why we allow such exception for contract
        branch.
        """
        return {
            sqlalchemy_obj_type: ['name']
            # For example: sa.Column: ['subnets.segment_id']
        }


HEAD files for conflict management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In directory ``neutron/db/migration/alembic_migrations/versions`` there are two
files, ``CONTRACT_HEAD`` and ``EXPAND_HEAD``. These files contain the ID of the
head revision in each branch. The purpose of these files is to validate the
revision timelines and prevent non-linear changes from entering the merge queue.

When you create a new migration script by neutron-db-manage these files will be
updated automatically. But if another migration script is merged while your
change is under review, you will need to resolve the conflict manually by
changing the ``down_revision`` in your migration script.

Applying database migration rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To apply just expansion rules, execute::

 neutron-db-manage upgrade --expand

After the first step is done, you can stop neutron-server, apply remaining
non-expansive migration rules, if any::

 neutron-db-manage upgrade --contract

and finally, start your neutron-server again.

If you have multiple neutron-server instances in your cloud, and there are
pending contract scripts not applied to the database, full shutdown of all
those services is required before 'upgrade --contract' is executed. You can
determine whether there are any pending contract scripts by checking the
message returned from the following command::

 neutron-db-manage has_offline_migrations

If you are not interested in applying safe migration rules while the service is
running, you can still upgrade database the old way, by stopping the service,
and then applying all available rules::

 neutron-db-manage upgrade head[s]

It will apply all the rules from both the expand and the contract branches, in
proper order.


Tagging milestone revisions
~~~~~~~~~~~~~~~~~~~~~~~~~~~

When named release (liberty, mitaka, etc.) is done for neutron or a
sub-project, the alembic revision scripts at the head of each branch for that
release must be tagged. This is referred to as a milestone revision tag.

For example, `here <https://review.opendev.org/228272>`_ is a patch that tags
the liberty milestone revisions for the neutron-fwaas sub-project. Note that
each branch (expand and contract) is tagged.

Tagging milestones allows neutron-db-manage to upgrade the schema to a
milestone release, e.g.::

 neutron-db-manage upgrade liberty


Generation of comparable metadata with current database schema
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Directory ``neutron/db/migration/models`` contains module ``head.py``, which
provides all database models at current HEAD. Its purpose is to create
comparable metadata with the current database schema. The database schema is
generated by alembic migration scripts. The models must match, and this is
verified by a model-migration sync test in Neutron's functional test suite.
That test requires all modules containing DB models to be imported by head.py
in order to make a complete comparison.

When adding new database models, developers must update this module, otherwise
the change will fail to merge.
