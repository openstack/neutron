Neutron Database Layer
======================

This section contains some common information that will be useful for
developers that need to do some db changes.

Difference between 'default' and 'server_default' parameters for columns
------------------------------------------------------------------------

For columns it is possible to set 'default' or 'server_default'. What is the
difference between them and why should they be used?

The explanation is quite simple:

*  `default <http://docs.sqlalchemy.org/en/rel_0_9/core/metadata.html#sqlalchemy.schema.Column.params.default>`_ - the default value that SQLAlchemy will specify in queries for creating instances of a given model;
*  `server_default <http://docs.sqlalchemy.org/en/rel_0_9/core/metadata.html#sqlalchemy.schema.Column.params.server_default>`_ - the default value for a column that SQLAlchemy will specify in DDL.

Summarizing, 'default' is useless in migrations and only 'server_default'
should be used. For synchronizing migrations with models server_default parameter
should also be added in model. If default value in database is not needed,
'server_default' should not be used. The declarative approach can be bypassed
(i.e. 'default' may be omitted in the model) if default is enforced through
business logic.


How we manage database migration rules
--------------------------------------

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

To apply just expansion rules, execute:

- neutron-db-manage upgrade liberty_expand@head

After the first step is done, you can stop neutron-server, apply remaining
non-expansive migration rules, if any:

- neutron-db-manage upgrade liberty_contract@head

and finally, start your neutron-server again.

If you are not interested in applying safe migration rules while the service is
running, you can still upgrade database the old way, by stopping the service,
and then applying all available rules:

- neutron-db-manage upgrade head[s]

It will apply all the rules from both the expand and the contract branches, in
proper order.


Expand and Contract Scripts
---------------------------

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
"contract" directives (the drop column moreso than the drop constraint); running
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


Tests to verify that database migrations and models are in sync
---------------------------------------------------------------

.. automodule:: neutron.tests.functional.db.test_migrations

.. autoclass:: _TestModelsMigrations
   :members:
