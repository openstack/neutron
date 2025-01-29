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

.. note::

    Much of this document discusses upgrade considerations for the Neutron
    reference implementation using Neutron's agents. It's expected that each
    Neutron plugin provides its own documentation that discusses upgrade
    considerations specific to that choice of backend. For example, OVN does
    not use Neutron agents, but does have a local controller that runs on each
    compute node. OVN supports rolling upgrades, but information about how that
    works should be covered in the documentation for the OVN Neutron plugin.

Upgrade strategy
================

There are two general upgrade scenarios supported by Neutron:

#. All services are shut down, code upgraded, then all services are started
   again.
#. Services are upgraded gradually, based on operator service windows.

The latter is the preferred way to upgrade an OpenStack cloud, since it allows
for more granularity and less service downtime. This scenario is usually called
'rolling upgrade'.

Rolling upgrade
---------------

Rolling upgrades imply that during some interval of time there will be services
of different code versions running and interacting in the same cloud. It puts
multiple constraints onto the software.

#. older services should be able to talk with newer services.
#. older services should not require the database to have older schema
   (otherwise newer services that require the newer schema would not work).

`More info on rolling upgrades in OpenStack
<https://governance.openstack.org/tc/reference/tags/assert_supports-rolling-upgrade.html>`_.

Those requirements are achieved in Neutron by:

#. If the Neutron backend makes use of Neutron agents, the Neutron server have
   backwards compatibility code to deal with older messaging payloads.
#. isolating a single service that accesses database (neutron-server).

To simplify the matter, it's always assumed that the order of service upgrades
is as following:

#. first, all neutron-servers are upgraded.
#. then, if applicable, neutron agents are upgraded.

This approach allows us to avoid backwards compatibility code on agent side and
is in line with other OpenStack projects that support rolling upgrades
(specifically, nova).

Server upgrade
~~~~~~~~~~~~~~

Neutron-server is the very first component that should be upgraded to the new
code. It's also the only component that relies on new database schema to be
present, other components communicate with the cloud through AMQP and hence do
not depend on particular database state.

Database upgrades are implemented with alembic migration chains.

Database upgrade is split into two parts:

#. ``neutron-db-manage upgrade --expand``
#. ``neutron-db-manage upgrade --contract``

Each part represents a separate alembic branch.

The former step can be executed while old neutron-server code is running. The
latter step requires *all* neutron-server instances to be shut down. Once it's
complete, neutron-servers can be started again.

.. note::
    Full shutdown of neutron-server instances can be skipped depending on
    whether there are pending contract scripts not applied to the database::

     $ neutron-db-manage has_offline_migrations
     Command will return a message if there are pending contract scripts.

:ref:`More info on alembic scripts <alembic_migrations>`.

Agents upgrade
~~~~~~~~~~~~~~

.. note::

    This section does not apply when the cloud does not use AMQP agents to
    provide networking services to instances. In that case, other backend
    specific upgrade instructions may also apply.

Once neutron-server services are restarted with the new database schema and the
new code, it's time to upgrade Neutron agents.

Note that in the meantime, neutron-server should be able to serve AMQP messages
sent by older versions of agents which are part of the cloud.

The recommended order of agent upgrade (per node) is:

#. first, L2 agents (openvswitch, sr-iov).
#. then, all other agents (L3, DHCP, Metadata, ...).

The rationale of the agent upgrade order is that L2 agent is usually
responsible for wiring ports for other agents to use, so it's better to allow
it to do its job first and then proceed with other agents that will use the
already configured ports for their needs.

Each network/compute node can have its own upgrade schedule that is independent
of other nodes.

AMQP considerations
+++++++++++++++++++

Since it's always assumed that neutron-server component is upgraded before
agents, only the former should handle both old and new RPC versions.

The implication of that is that no code that handles UnsupportedVersion
oslo.messaging exceptions belongs to agent code.

Notifications
'''''''''''''

For notifications that are issued by neutron-server to listening agents,
special consideration is needed to support rolling upgrades. In this case, a
newer controller sends newer payload to older agents.

Until we have proper RPC version pinning feature to enforce older payload
format during upgrade (as it's implemented in other projects like nova), we
leave our agents resistant against unknown arguments sent as part of server
notifications. This is achieved by consistently capturing those unknown
arguments with keyword arguments and ignoring them on agent side; and by not
enforcing newer RPC entry point versions on server side.

This approach is not ideal, because it makes RPC API less strict. That's why
other approaches should be considered for notifications in the future.

:ref:`More information about RPC versioning <rpc_versioning>`.

Interface signature
'''''''''''''''''''

An RPC interface is defined by its name, version, and (named) arguments that
it accepts. There are no strict guarantees that arguments will have expected
types or meaning, as long as they are serializable.

Message content versioning
''''''''''''''''''''''''''

To provide better compatibility guarantees for rolling upgrades, RPC interfaces
could also define specific format for arguments they accept. In OpenStack
world, it's usually implemented using oslo.versionedobjects library, and
relying on the library to define serialized form for arguments that are passed
through AMQP wire.

Note that Neutron has *not* adopted oslo.versionedobjects library for its RPC
interfaces yet (except for QoS feature).

:ref:`More information about RPC callbacks used for QoS <rpc_callbacks>`.

Networking backends
~~~~~~~~~~~~~~~~~~~

Backend software upgrade should not result in any data plane disruptions.
Meaning, e.g. Open vSwitch L2 agent should not reset flows or rewire ports;
Neutron L3 agent should not delete namespaces left by older version of the
agent; Neutron DHCP agent should not require immediate DHCP lease renewal; etc.

The same considerations apply to setups that do not rely on agents. Meaning,
f.e. OpenDaylight or OVN controller should not break data plane connectivity
during its upgrade process.

Upgrade testing
---------------

`Grenade <https://github.com/openstack-dev/grenade>`_ is the OpenStack project
that is designed to validate upgrade scenarios.

Currently, only offline (non-rolling) upgrade scenario is validated in Neutron
gate. The upgrade scenario follows the following steps:

#. the 'old' cloud is set up using latest stable release code
#. all services are stopped
#. code is updated to the patch under review
#. new database migration scripts are applied, if needed
#. all services are started
#. the 'new' cloud is validated with a subset of tempest tests

The scenario validates that no configuration option names are changed in one
cycle. More generally, it validates that the 'new' cloud is capable of running
using the 'old' configuration files. It also validates that database migration
scripts can be executed.

The scenario does *not* validate AMQP versioning compatibility.

Other projects (for example Nova) have so called 'partial' grenade jobs where
some services are left running using the old version of code. Such a job would
be needed in Neutron gate to validate rolling upgrades for the project. Till
that time, it's all up to reviewers to catch compatibility issues in patches on
review.

Another hole in testing belongs to split migration script branches. It's
assumed that an 'old' cloud can successfully run after 'expand' migration
scripts from the 'new' cloud are applied to its database; but it's not
validated in gate.

.. _upgrade_review_guidelines:

Review guidelines
-----------------

There are several upgrade related gotchas that should be tracked by reviewers.

First things first, a general advice to reviewers: make sure new code does not
violate requirements set by `global OpenStack deprecation policy
<https://governance.openstack.org/tc/reference/tags/assert_follows-standard-deprecation.html>`_.

Now to specifics:

#. Configuration options:

   * options should not be dropped from the tree without waiting for
     deprecation period (currently it's one development cycle long) and a
     deprecation message issued if the deprecated option is used.
   * option values should not change their meaning between releases.

#. Data plane:

   * agent restart should not result in data plane disruption (no Open vSwitch
     ports reset; no network namespaces deleted; no device names changed).

#. RPC versioning:

   * no RPC version major number should be bumped before all agents had a
     chance to upgrade (meaning, at least one release cycle is needed before
     compatibility code to handle old clients is stripped from the tree).
   * no compatibility code should be added to agent side of AMQP interfaces.
   * server code should be able to handle all previous versions of agents,
     unless the major version of an interface is bumped.
   * no RPC interface arguments should change their meaning, or names.
   * new arguments added to RPC interfaces should not be mandatory. It means
     that server should be able to handle old requests, without the new
     argument specified. Also, if the argument is not passed, the old behaviour
     before the addition of the argument should be retained.
   * minimal client version must not be bumped for server initiated
     notification changes for at least one cycle.

#. Database migrations:

   * migration code should be split into two branches (contract, expand) as
     needed. No code that is unsafe to execute while neutron-server is running
     should be added to expand branch.
   * if possible, contract migrations should be minimized or avoided to reduce
     the time when API endpoints must be down during database upgrade.
