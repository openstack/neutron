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
