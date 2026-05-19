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


Calling the ML2 Plugin
======================

When writing code for an extension, service plugin, or any other part of
Neutron you must not call core plugin methods that mutate state while
you have a transaction open on the session that you pass into the core
plugin method.

The create and update methods for ports, networks, and subnets in ML2
all have a precommit phase and postcommit phase. During the postcommit
phase, the data is expected to be fully persisted to the database and
ML2 drivers will use this time to relay information to a backend outside
of Neutron. Calling the ML2 plugin within a transaction would violate
this semantic because the data would not be persisted to the DB; and,
were a failure to occur that caused the whole transaction to be rolled
back, the backend would become inconsistent with the state in Neutron's
DB.

To prevent this, these methods are protected with a decorator that will
raise a RuntimeError if they are called with context that has a session
in an active transaction. The decorator can be found at
neutron.common.utils.transaction_guard and may be used in other places
in Neutron to protect functions that are expected to be called outside
of a transaction.

Hierarchical Port Binding and Teardown Order
--------------------------------------------

Ports can be bound across multiple levels of network infrastructure. During
binding, each mechanism driver that successfully claims a level appends a
``PortBindingLevel`` record, producing an ordered stack:

* **Level 0** — outermost, closest to the network fabric (e.g. spine switch),
  bound first.
* **Level N** — innermost, closest to the compute host (e.g. ToR switch or
  hypervisor vswitch), bound last.

This is a **FILO (first-in, last-out)** structure. The driver that binds
level 0 is the first driver in the configured ``mechanism_drivers`` list that
succeeds, and subsequent levels are populated by drivers called in the same
forward order.

Teardown must mirror this in reverse: the innermost level must be cleaned up
before the outermost, so that each layer is removed before the infrastructure
beneath it is torn down. Accordingly, ``delete_port_precommit`` and
``delete_port_postcommit`` notify all mechanism drivers in **reverse**
configured order — opposite to the forward order used by all other lifecycle
callbacks (``create_*``, ``update_*``).

Mechanism driver authors should be aware of this contract:

* ``create_port_precommit`` / ``create_port_postcommit`` — forward order.
* ``update_port_precommit`` / ``update_port_postcommit`` — forward order.
* ``delete_port_precommit`` / ``delete_port_postcommit`` — **reverse order**.

A driver's ``delete_port_precommit`` and ``delete_port_postcommit``
implementations can inspect ``context.binding_levels`` to determine which
level(s) they are responsible for. Drivers that did not participate in
binding a particular port will still be called (the full driver list is always
walked); a driver that has nothing to clean up for a given port should simply
return.
