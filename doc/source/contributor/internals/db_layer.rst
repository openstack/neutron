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


Neutron Database Layer
======================

This section contains some common information that will be useful for
developers that need to do some database changes as well as to execute queries
using the oslo.db API.

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


Database migrations
-------------------

For details on the neutron-db-manage wrapper and alembic migrations, see
`Alembic Migrations <alembic_migrations.html>`_.

.. _testing-database-migrations:

Tests to verify that database migrations and models are in sync
---------------------------------------------------------------

.. automodule:: neutron.tests.functional.db.test_migrations

.. autoclass:: _TestModelsMigrations
   :members:


The Standard Attribute Table
----------------------------

There are many attributes that we would like to store in the database which
are common across many Neutron objects (e.g. tags, timestamps, rbac entries).
We have previously been handling this by duplicating the schema to every table
via model mixins. This means that a DB migration is required for each object
that wants to adopt one of these common attributes. This becomes even more
cumbersome when the relationship between the attribute and the object is
many-to-one because each object then needs its own table for the attributes
(assuming referential integrity is a concern).

To address this issue, the 'standardattribute' table is available. Any model
can add support for this table by inheriting the 'HasStandardAttributes' mixin
in neutron.db.standard_attr. This mixin will add a standard_attr_id BigInteger
column to the model with a foreign key relationship to the 'standardattribute'
table. The model will then be able to access any columns of the
'standardattribute' table and any tables related to it.

A model that inherits HasStandardAttributes must implement the property
'api_collections', which is a list of API resources that the new object
may appear under. In most cases, this will only be one (e.g. 'ports' for
the Port model). This is used by all of the service plugins that add standard
attribute fields to determine which API responses need to be populated.

A model that supports tag mechanism must implement the property
'collection_resource_map' which is a dict of 'collection_name' and
'resource_name' for API resources. And also the model must implement
'tag_support' with a value True.

The introduction of a new standard attribute only requires one column addition
to the 'standardattribute' table for one-to-one relationships or a new table
for one-to-many or one-to-zero relationships. Then all of the models using the
'HasStandardAttribute' mixin will automatically gain access to the new attribute.

Any attributes that will apply to every neutron resource (e.g. timestamps)
can be added directly to the 'standardattribute' table. For things that will
frequently be NULL for most entries (e.g. a column to store an error reason),
a new table should be added and joined to in a query to prevent a bunch of
NULL entries in the database.


Session handling
----------------

The main information reference is in `Usage <https://opendev.org/openstack/oslo.db/src/branch/master/doc/source/user/usage.rst>`_,
that provides an initial picture of how to use oslo.db in Neutron. Any request
call to the Neutron server API must have a "neutron_context" parameter, that is
an instance of `Context <https://opendev.org/openstack/neutron-lib/src/tag/2.21.0/neutron_lib/context.py#L142>`_.
This context holds a `sqlalchemy.orm.session.Session` instance that "manages
persistence operations for ORM-mapped objects" (from SQLAlchemy documentation).
A `Session` establishes all conversations with the database and represents a
"holding zone" for all loaded or associated objects during its lifespan.

A `Session` instance establishes a transaction to the database using the
defined `Engine`. This transaction represents an SQL transaction that is "a
logical unit of work that contains one or more SQL statements". Regardless of
the number of statements this transaction may have, the execution is atomic; if
the transaction fails, any previous SQL statement already executed that implies
a change in the database is undone (rollback).


Database transactions
---------------------

Any Neutron database operation, regardless of the type and the amount, should
be executed inside a transaction. There are two type of transactions:

* Reader: for reading operations.
* Writer: for any operation that implies a change in the database, like a
  register creation, modification or deletion.


The neutron-lib library provides an API wrapper for the oslo.db operations.
The `CONTEXT_READER` and `CONTEXT_WRITER` context managers can be used both
as decorators or context managers. For example:

.. code-block:: python

    from neutron_lib.db import api as db_api
    from neutron.db import models_v2

    def get_ports(context, network_id):
        with db_api.CONTEXT_READER.using(context):
            query = context.session.query(models_v2.Port)
            query.filter(models_v2.Port.network_id == network_id)
            return query.all()

    @db_api.CONTEXT_WRITER
    def delete_port(context, port_id)
        query = context.session.query(models_v2.Port)
        query.filter(models_v2.Port.id == port_id)
        query.delete()


The transaction contexts can be nested. For example, if inside a context a
decorated method is called, the current transaction is preserved. There is only
one exception on this rule: a reader context cannot be upgraded to writer. That
means inside a reader context it is not possible to start a writer context. The
following exception will be raised:

.. code-block:: python

    TypeError: Can't upgrade a READER transaction to a WRITER mid-transaction


Another consideration that must be taken when implementing/reviewing new code
is that, as commented before, a transaction is an atomic operation on the
database. If the database layer (SQLAlchemy, oslo.db) returns a database
exception, the current active transaction should end. In other words, we can
catch, if needed, the exception raised and retry any needed operation, but any
further database command should be executed in a new context. This is needed to
allow the context wrapper (writer, reader) to properly finish the operation,
for example rolling back the already executed commands. Check the patch
`<https://review.opendev.org/c/openstack/neutron/+/843263>`_ as an example of
how to handle database exceptions.


Retry decorators
----------------

This is an appendix for
:doc:`/contributor/internals/retries`

This is also related to the previous section. The neutron-lib library provides
a decorator called `retry_if_session_inactive` that can be used to retry
any method if the context session is not active; in other words, there is no
active transaction when the method is called. The session is retrieved from
the "context" parameter passed into the method (it is a must to have this
parameter in the method signature).

This retry decorator can be used along with a transaction decorator but the
retry decorator must be declared before the context one. If we first declare
the database context (writer or reader) and then the retry decorator, the retry
context would be always called from inside an active transaction making it
useless. An example of a good implementation (first the retry decorator and
then the reader one):

.. code-block:: python

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def get_ports_count(self, context, filters=None):
        return self._get_ports_query(context, filters).count()
