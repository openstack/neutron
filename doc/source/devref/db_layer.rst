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


Tests to verify that database migrations and models are in sync
---------------------------------------------------------------

.. automodule:: neutron.tests.functional.db.test_migrations

.. autoclass:: _TestModelsMigrations
   :members:
