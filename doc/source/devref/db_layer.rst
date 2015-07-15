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


Tests to verify that database migrations and models are in sync
---------------------------------------------------------------

.. automodule:: neutron.tests.functional.db.test_migrations

.. autoclass:: _TestModelsMigrations
   :members:
