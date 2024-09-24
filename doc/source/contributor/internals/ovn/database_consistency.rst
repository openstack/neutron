.. _database_consistency:

================================
Neutron/OVN Database consistency
================================

This document presents the problem and proposes a solution for the data
consistency issue between the Neutron and OVN databases. Although the
focus of this document is OVN this problem is common enough to be present
in other ML2 drivers (e.g OpenDayLight, BigSwitch, etc...). Some of them
already contain a mechanism in place for dealing with it.

Problem description
===================

In a common Neutron deployment model there could have multiple Neutron
API workers processing requests. For each request, the worker will update
the Neutron database and then invoke the ML2 driver to translate the
information to that specific SDN data model.

There are at least two situations that could lead to some inconsistency
between the Neutron and the SDN databases, for example:

.. _problem_1:

Problem 1: Neutron API workers race condition
---------------------------------------------

.. code-block:: python

  In Neutron:
    with neutron_db_transaction:
         update_neutron_db()
         ml2_driver.update_port_precommit()
    ml2_driver.update_port_postcommit()

  In the ML2 driver:
    def update_port_postcommit:
        port = neutron_db.get_port()
        update_port_in_ovn(port)

Imagine the case where a port is being updated twice and each request
is being handled by a different API worker. The method responsible for
updating the resource in the OVN (``update_port_postcommit``) is not
atomic and invoked outside of the Neutron database transaction. This could
lead to a problem where the order in which the updates are committed to
the Neutron database are different than the order that they are committed
to the OVN database, resulting in an inconsistency.

This problem has been reported at `bug #1605089
<https://bugs.launchpad.net/networking-ovn/+bug/1605089>`_.

.. _problem_2:

Problem 2: Backend failures
---------------------------

Another situation is when the changes are already committed in Neutron
but an exception is raised upon trying to update the OVN database (e.g
lost connectivity to the ``ovsdb-server``). We currently don't have a
good way of handling this problem, obviously it would be possible to try
to immediately rollback the changes in the Neutron database and raise an
exception but, that rollback itself is an operation that could also fail.

Plus, rollbacks is not very straight forward when it comes to updates
or deletes. In a case where a VM is being teared down and OVN fail to
delete a port, re-creating that port in Neutron doesn't necessary fix the
problem. The decommission of a VM involves many other things, in fact, we
could make things even worse by leaving some dirty data around. I believe
this is a problem that would be better dealt with by other methods.

Proposed change
===============

In order to fix the problems presented at the `Problem description`_
section this document proposes a solution based on the Neutron's
``revision_number`` attribute. In summary, for every resource in Neutron
there's an attribute called ``revision_number`` which gets incremented
on each update made on that resource. For example::

 $ openstack port create --network nettest porttest
 ...
 | revision_number | 2 |
 ...

 $ openstack port set porttest --mac-address 11:22:33:44:55:66

 $ mysql -e "use neutron; select standard_attr_id from ports where id=\"91c08021-ded3-4c5a-8d57-5b5c389f8e39\";"
 +------------------+
 | standard_attr_id |
 +------------------+
 |             1427 |
 +------------------+

 $ mysql -e "use neutron; SELECT revision_number FROM standardattributes WHERE id=1427;"
 +-----------------+
 | revision_number |
 +-----------------+
 |               3 |
 +-----------------+


This document proposes a solution that will use the `revision_number`
attribute for three things:

#. Perform a compare-and-swap operation based on the resource version
#. Guarantee the order of the updates (`Problem 1 <problem_1_>`_)
#. Detecting when resources in Neutron and OVN are out-of-sync

But, before any of points above can be done we need to change the
ovn driver code to:


#1 - Store the revision_number referent to a change in OVNDB
------------------------------------------------------------

To be able to compare the version of the resource in Neutron against
the version in OVN we first need to know which version the OVN resource
is present at.

Fortunately, each table in the OVNDB contains a special column called
``external_ids`` which external systems (like Neutron)
can use to store information about its own resources that corresponds
to the entries in OVNDB.

So, every time a resource is created or updated in OVNDB by
ovn driver, the Neutron ``revision_number`` referent to that change
will be stored in the ``external_ids`` column of that resource. That
will allow ovn driver to look at both databases and detect whether
the version in OVN is up-to-date with Neutron or not.


#2 - Ensure correctness when updating OVN
-----------------------------------------

As stated in `Problem 1 <problem_1_>`_, simultaneous updates to a single
resource will race and, with the current code, the order in which these
updates are applied is not guaranteed to be the correct order. That
means that, if two or more updates arrives we can't prevent an older
version of that update to be applied after a newer one.

This document proposes creating a special ``OVSDB command`` that runs
as part of the same transaction that is updating a resource in OVNDB to
prevent changes with a lower ``revision_number`` to be applied in case
the resource in OVN is at a higher ``revision_number`` already.

This new OVSDB command needs to basically do two things:

1. Add a verify operation to the ``external_ids`` column in OVNDB so
that if another client modifies that column mid-operation the transaction
will be restarted.

A better explanation of what "verify" does is described at the doc string
of the `Transaction class`_ in the OVS code itself, I quote:

 Because OVSDB handles multiple clients, it can happen that between
 the time that OVSDB client A reads a column and writes a new value,
 OVSDB client B has written that column.  Client A's write should not
 ordinarily overwrite client B's, especially if the column in question
 is a "map" column that contains several more or less independent data
 items.  If client A adds a "verify" operation before it writes the
 column, then the transaction fails in case client B modifies it first.
 Client A will then see the new value of the column and compose a new
 transaction based on the new contents written by client B.

2. Compare the ``revision_number`` from the update against what is
presently stored in OVNDB. If the version in OVNDB is already higher
than the version in the update, abort the transaction.

So basically this new command is responsible for guarding the OVN resource
by not allowing old changes to be applied on top of new ones. Here's a
scenario where two concurrent updates comes in the wrong order and how
the solution above will deal with it:

Neutron worker 1 (NW-1): Updates a port with address A (revision_number: 2)

Neutron worker 2 (NW-2): Updates a port with address B (revision_number: 3)

TXN 1: NW-2 transaction is committed first and the OVN resource now has RN 3

TXN 2: NW-1 transaction detects the change in the external_ids column and
is restarted

TXN 2: NW-1 the new command now sees that the OVN resource is at RN 3,
which is higher than the update version (RN 2) and aborts the transaction.

There's a bit more for the above to work with the current ovn driver
code, basically we need to tidy up the code to do two more things.

1. Consolidate changes to a resource in a single transaction.

This is important regardless of this spec, having all changes to a
resource done in a single transaction minimizes the risk of having
half-changes written to the database in case of an eventual problem. This
`should be done already <https://review.openstack.org/#/c/515673>`_
but it's important to have it here in case we find more examples like
that as we code.

2. When doing partial updates, use the OVNDB as the source of comparison
to create the deltas.

Being able to do a partial update in a resource is important for
performance reasons; it's a way to minimize the number of changes that
will be performed in the database.

Right now, some of the update() methods in ovn driver creates the
deltas using the *current* and *original* parameters that are passed to
it. The *current* parameter is, as the name says, the current version
of the object present in the Neutron DB. The *original* parameter is
the previous version (current - 1) of that object.

The problem of creating the deltas by comparing these two objects is
because only the data in the Neutron DB is used for it. We need to stop
using the *original* object for it and instead we should create the
delta based on the *current* version of the Neutron DB against the data
stored in the OVNDB to be able to detect the real differences between
the two databases.

So in summary, to guarantee the correctness of the updates this document
proposes to:

#. Create a new OVSDB command is responsible for comparing revision
   numbers and aborting the transaction, when needed.
#. Consolidate changes to a resource in a single transaction (should be
   done already)
#. When doing partial updates, create the deltas based in the current
   version in the Neutron DB and the OVNDB.


#3 - Detect and fix out-of-sync resources
-----------------------------------------

When things are working as expected the above changes should ensure
that Neutron DB and OVNDB are in sync but, what happens when things go
bad ? As per `Problem 2 <problem_2_>`_, things like temporarily losing
connectivity with the OVNDB could cause changes to fail to be committed
and the databases getting out-of-sync. We need to be able to detect the
resources that were affected by these failures and fix them.

We do already have the means to do it, similar to what the
`ovn_db_sync.py`_ script does we could fetch all the data from both
databases and compare each resource. But, depending on the size of the
deployment this can be really slow and costy.

This document proposes an optimization for this problem  to make it
efficient enough so that we can run it periodically (as a periodic task)
and not manually as a script anymore.

First, we need to create an additional table in the Neutron database
that would serve as a cache for the revision numbers in **OVNDB**.

The new table schema could look this:

================  ========  =================================================
Column name       Type      Description
================  ========  =================================================
standard_attr_id  Integer   Primary key. The reference ID from the
                            standardattributes table in Neutron for
                            that resource. ONDELETE SET NULL.
resource_uuid     String    The UUID of the resource
resource_type     String    The type of the resource (e.g, Port, Router, ...)
revision_number   Integer   The version of the object present in OVN
acquired_at       DateTime  The time that the entry was create. For
                            troubleshooting purposes
updated_at        DateTime  The time that the entry was updated. For
                            troubleshooting purposes
================  ========  =================================================

For the different actions: Create, update and delete; this table will be
used as:


1. Create:

In the create_*_precommit() method, we will create an entry in the new
table within the same Neutron transaction. The revision_number column
for the new entry will have a placeholder value until the resource is
successfully created in OVNDB.

In case we fail to create the resource in OVN (but succeed in Neutron)
we still have the entry logged in the new table and this problem can
be detected by fetching all resources where the revision_number column
value is equal to the placeholder value.

The pseudo-code will look something like this:

.. code-block:: python

    def create_port_precommit(ctx, port):
        create_initial_revision(port['id'], revision_number=-1,
                                session=ctx.session)

    def create_port_postcommit(ctx, port):
        create_port_in_ovn(port)
        bump_revision(port['id'], revision_number=port['revision_number'])


2. Update:

For update it's simpler, we need to bump the revision number for
that resource **after** the OVN transaction is committed in the
update_*_postcommit() method. That way, if an update fails to be applied
to OVN the inconsistencies can be detected by a JOIN between the new
table and the ``standardattributes`` table where the revision_number
columns does not match.

The pseudo-code will look something like this:

.. code-block:: python

    def update_port_postcommit(ctx, port):
        update_port_in_ovn(port)
        bump_revision(port['id'], revision_number=port['revision_number'])


3. Delete:

The ``standard_attr_id`` column in the new table is a foreign key
constraint with a ``ONDELETE=SET NULL`` set. That means that, upon
Neutron deleting a resource the ``standard_attr_id`` column in the new
table will be set to *NULL*.

If deleting a resource succeeds in Neutron but fails in OVN, the
inconsistency can be detect by looking at all resources that has a
``standard_attr_id`` equals to NULL.

The pseudo-code will look something like this:

.. code-block:: python

    def delete_port_postcommit(ctx, port):
        delete_port_in_ovn(port)
        delete_revision(port['id'])


With the above optimization it's possible to create a periodic task that
can run quite frequently to detect and fix the inconsistencies caused
by random backend failures.

.. note::
   There's no lock linking both database updates in the postcommit()
   methods. So, it's true that the method bumping the revision_number
   column in the new table in Neutron DB could still race but, that
   should be fine because this table acts like a cache and the real
   revision_number has been written in OVNDB.

   The mechanism that will detect and fix the out-of-sync resources should
   detect this inconsistency as well and, based on the revision_number
   in OVNDB, decide whether to sync the resource or only bump the
   revision_number in the cache table (in case the resource is already
   at the right version).


Refereces
=========

* There's a chain of patches with a proof of concept for this approach,
  they start at: https://review.openstack.org/#/c/517049/

Alternatives
============

Journaling
----------

An alternative solution to this problem is *journaling*. The basic
idea is to create another table in the Neutron database and log every
operation (create, update and delete) instead of passing it directly to
the SDN controller.

A separated thread (or multiple instances of it) is then responsible
for reading this table and applying the operations to the SDN backend.

This approach has been used and validated
by drivers such as `networking-odl
<https://docs.openstack.org/networking-odl/latest/contributor/drivers_architecture.html#v2-design>`_.

An attempt to implement this approach
in *ovn driver* can be found `here
<https://review.openstack.org/#/q/project:openstack/networking-ovn+topic:bug/1605089-journaling>`_.

Some things to keep in mind about this approach:

* The code can get quite complex as this approach is not only about
  applying the changes to the SDN backend asynchronously. The dependencies
  between each resource as well as their operations also needs to be
  computed. For example, before attempting to create a router port the
  router that this port belongs to needs to be created. Or, before
  attempting to delete a network all the dependent resources on it
  (subnets, ports, etc...) needs to be processed first.

* The number of journal threads running can cause problems. In my tests
  I had three controllers, each one with 24 CPU cores (Intel Xeon E5-2620
  with hyperthreading enabled) and 64GB RAM. Running 1 journal thread
  per Neutron API worker has caused ``ovsdb-server`` to misbehave
  when under heavy pressure [1]_. Running multiple journal threads
  seem to be causing other types of problems `in other drivers as well
  <https://bugs.launchpad.net/networking-odl/+bug/1683797>`_.

* When under heavy pressure [1]_, I noticed that the journal
  threads could come to a halt (or really slowed down) while the
  API workers were handling a lot of requests. This resulted in some
  operations taking more than a minute to be processed. This behaviour
  can be seem `in this screenshot <http://i.imgur.com/GDG8Mic.png>`_.

.. TODO find a better place to host that image

* Given that the 1 journal thread per Neutron API worker approach
  is problematic, determining the right number of journal threads is
  also difficult. In my tests, I've noticed that 3 journal threads
  per controller worked better but that number was pure based on
  ``trial & error``. In production this number should probably be
  calculated based in the environment.

* At least temporarily, the data in the Neutron database is duplicated
  between the normal tables and the journal one.

* Some operations like creating a new
  resource via Neutron's API will return `HTTP 201
  <https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#2xx_Success>`_,
  which indicates that the resource has been created and is ready to
  be used, but as these resources are created asynchronously one could
  argue that the HTTP codes are now misleading. As a note, the resource
  will be created at the Neutron database by the time the HTTP request
  returns but it may not be present in the SDN backend yet.

Given all considerations, this approach is still valid and the fact
that it's already been used by other ML2 drivers makes it more open for
collaboration and code sharing.

.. _`Transaction class`: https://github.com/openvswitch/ovs/blob/3728b3b0316b44d1f9181be115b63ea85ff5883c/python/ovs/db/idl.py#L1014-L1055

.. _`ovn_db_sync.py`: https://github.com/openstack/networking-ovn/blob/a9af75cd3ce6cd6685b6435b325c97cacc83ce0e/networking_ovn/ovn_db_sync.py

.. rubric:: Footnotes

.. [1] I ran the tests using `Browbeat
  <https://github.com/openstack/browbeat>`_ which is basically orchestrate
  `Openstack Rally <https://github.com/openstack/rally>`_ and monitor the
  machine's usage of resources.
