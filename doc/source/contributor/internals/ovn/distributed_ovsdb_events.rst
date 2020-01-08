.. _distributed_ovsdb_events:

================================
Distributed OVSDB events handler
================================

This document presents the problem and proposes a solution for handling
OVSDB events in a distributed fashion in ovn driver.

Problem description
===================

In ovn driver, the OVSDB Monitor class is responsible for listening
to the OVSDB events and performing certain actions on them. We use it
extensively for various tasks including critical ones such as monitoring
for port binding events (in order to notify Neutron/Nova that a port
has been bound to a certain chassis). Currently, this class uses a
distributed OVSDB lock to ensure that only one instance handles those
events at a time.

The problem with this approach is that it creates a bottleneck because
even if we have multiple Neutron Workers running at the moment, only one
is actively handling those events. And, this problem is highlighted even
more when working with technologies such as containers which rely on
creating multiple ports at a time and waiting for them to be bound.

Proposed change
===============

In order to fix this problem, this document proposes using a `Consistent
Hash Ring`_ to split the load of handling events across multiple Neutron
Workers.

A new table called ``ovn_hash_ring`` will be created in the Neutron
Database where the Neutron Workers capable of handling OVSDB events will
be registered. The table will use the following schema:

================  ========  =================================================
Column name       Type      Description
================  ========  =================================================
node_uuid         String    Primary key. The unique identification of a
                            Neutron Worker.
hostname          String    The hostname of the machine this Node is running
                            on.
created_at        DateTime  The time that the entry was created. For
                            troubleshooting purposes.
updated_at        DateTime  The time that the entry was updated. Used as a
                            heartbeat to indicate that the Node is still
                            alive.
================  ========  =================================================

This table will be used to form the `Consistent Hash Ring`_. Fortunately,
we have an implementation already in the `tooz`_ library of OpenStack. It
was contributed by the `Ironic`_ team which also uses this data
structure in order to spread the API request load across multiple
Ironic Conductors.

Here's how a `Consistent Hash Ring`_ from `tooz`_ works::

  from tooz import hashring

  hring = hashring.HashRing({'worker1', 'worker2', 'worker3'})

  # Returns set(['worker3'])
  hring[b'event-id-1']

  # Returns set(['worker1'])
  hring[b'event-id-2']


How OVSDB Monitor will use the Ring
-----------------------------------

Every instance of the OVSDB Monitor class will be listening to a series
of events from the OVSDB database and each of them will have a unique
ID registered in the database which will be part of the `Consistent
Hash Ring`.

When an event arrives, each OVSDB Monitor instance will hash that
event UUID and the ring will return one instance ID, which will then
be compared with its own ID and if it matches that instance will then
process the event.

Verifying status of OVSDB Monitor instance
------------------------------------------

A new maintenance task will be created in ovn driver which will
update the ``updated_at`` column from the ``ovn_hash_ring`` table for
the entries matching its hostname indicating that all Neutron Workers
running on that hostname are alive.

Note that only a single maintenance instance runs on each machine so
the writes to the Neutron database are optimized.

When forming the ring, the code should check for entries where the
value of ``updated_at`` column is newer than a given timeout. Entries
that haven't been updated in a certain time won't be part of the ring.
If the ring already exists it will be re-balanced.

Clean up and minimizing downtime window
---------------------------------------

Apart from heartbeating, we need to make sure that we remove the Nodes
from the ring when the service is stopped or killed.

By stopping the ``neutron-server`` service, all Nodes sharing the same
hostname as the machine where the service is running will be removed
from the ``ovn_hash_ring`` table. This is done by handling the SIGTERM
event. Upon this event arriving, ovn driver should invoke the clean
up method and then let the process halt.

Unfortunately nothing can be done in case of a SIGKILL, this will leave
the nodes in the database and they will be part of the ring until the
timeout is reached or the service is restarted. This can introduce a
window of time which can result in some events being lost. The current
implementation shares the same problem, if the instance holding the
current OVSDB lock is killed abruptly, events will be lost until the lock
is moved on to the next instance which is alive. One could argue that
the current implementation aggravates the problem because all events
will be lost where with the distributed mechanism **some** events will
be lost. As far as distributed systems goes, that's a normal scenario
and things are soon corrected.

Ideas for future improvements
-----------------------------

This section contains some ideas that can be added on top of this work
to further improve it:

* Listen to changes to the Chassis table in the OVSDB and force a ring
  re-balance when a Chassis is added or removed from it.

* Cache the ring for a short while to minimize the database reads when
  the service is under heavy load.

* To greater minimize/avoid event losses it would be possible to cache the
  last X events to be reprocessed in case a node times out and the
  ring re-balances.

.. _`Consistent Hash Ring`: https://en.wikipedia.org/wiki/Consistent_hashing
.. _`tooz`: https://github.com/openstack/tooz
.. _`Ironic`: https://github.com/openstack/ironic
