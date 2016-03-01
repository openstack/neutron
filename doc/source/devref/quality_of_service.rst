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


Quality of Service
==================

Quality of Service advanced service is designed as a service plugin. The
service is decoupled from the rest of Neutron code on multiple levels (see
below).

QoS extends core resources (ports, networks) without using mixins inherited
from plugins but through an ml2 extension driver.

Details about the DB models, API extension, and use cases can be found here: `qos spec <http://specs.openstack.org/openstack/neutron-specs/specs/liberty/qos-api-extension.html>`_
.

Service side design
-------------------

* neutron.extensions.qos:
  base extension + API controller definition. Note that rules are subattributes
  of policies and hence embedded into their URIs.

* neutron.services.qos.qos_plugin:
  QoSPlugin, service plugin that implements 'qos' extension, receiving and
  handling API calls to create/modify policies and rules.

* neutron.services.qos.notification_drivers.manager:
  the manager that passes object notifications down to every enabled
  notification driver.

* neutron.services.qos.notification_drivers.qos_base:
  the interface class for pluggable notification drivers that are used to
  update backends about new {create, update, delete} events on any rule or
  policy change.

* neutron.services.qos.notification_drivers.message_queue:
  MQ-based reference notification driver which updates agents via messaging
  bus, using `RPC callbacks <rpc_callbacks.html>`_.

* neutron.core_extensions.base:
  Contains an interface class to implement core resource (port/network)
  extensions. Core resource extensions are then easily integrated into
  interested plugins. We may need to  have a core resource extension manager
  that would utilize those extensions, to avoid plugin modifications for every
  new core resource extension.

* neutron.core_extensions.qos:
  Contains QoS core resource extension that conforms to the interface described
  above.

* neutron.plugins.ml2.extensions.qos:
  Contains ml2 extension driver that handles core resource updates by reusing
  the core_extensions.qos module mentioned above. In the future, we would like
  to see a plugin-agnostic core resource extension manager that could be
  integrated into other plugins with ease.


Supported QoS rule types
~~~~~~~~~~~~~~~~~~~~~~~~

Any plugin or Ml2 mechanism driver can claim support for some QoS rule types by
providing a plugin/driver class property called 'supported_qos_rule_types' that
should return a list of strings that correspond to QoS rule types (for the list
of all rule types, see: neutron.services.qos.qos_consts.VALID_RULE_TYPES).

In the most simple case, the property can be represented by a simple Python
list defined on the class.

For Ml2 plugin, the list of supported QoS rule types is defined as a common
subset of rules supported by all active mechanism drivers.

Note: the list of supported rule types reported by core plugin is not enforced
when accessing QoS rule resources. This is mostly because then we would not be
able to create any rules while at least one ml2 driver in gate lacks support
for QoS (at the moment of writing, linuxbridge is such a driver).


Database models
~~~~~~~~~~~~~~~

QoS design defines the following two conceptual resources to apply QoS rules
for a port or a network:

* QoS policy
* QoS rule (type specific)

Each QoS policy contains zero or more QoS rules. A policy is then applied to a
network or a port, making all rules of the policy applied to the corresponding
Neutron resource.

When applied through a network association, policy rules could apply or not
to neutron internal ports (like router, dhcp, load balancer, etc..). The QosRule
base object provides a default should_apply_to_port method which could be
overridden. In the future we may want to have a flag in QoSNetworkPolicyBinding
or QosRule to enforce such type of application (for example when limiting all
the ingress of routers devices on an external network automatically).

From database point of view, following objects are defined in schema:

* QosPolicy: directly maps to the conceptual policy resource.
* QosNetworkPolicyBinding, QosPortPolicyBinding: defines attachment between a
  Neutron resource and a QoS policy.
* QosBandwidthLimitRule: defines the only rule type available at the moment.


All database models are defined under:

* neutron.db.qos.models


QoS versioned objects
~~~~~~~~~~~~~~~~~~~~~

There is a long history of passing database dictionaries directly into business
logic of Neutron. This path is not the one we wanted to take for QoS effort, so
we've also introduced a new objects middleware to encapsulate the database logic
from the rest of the Neutron code that works with QoS resources. For this, we've
adopted oslo.versionedobjects library and introduced a new NeutronObject class
that is a base for all other objects that will belong to the middle layer.
There is an expectation that Neutron will evolve into using objects for all
resources it handles, though that part was obviously out of scope for the QoS
effort.

Every NeutronObject supports the following operations:

* get_by_id: returns specific object that is represented by the id passed as an
  argument.
* get_objects: returns all objects of the type, potentially with a filter
  applied.
* create/update/delete: usual persistence operations.

Base object class is defined in:

* neutron.objects.base

For QoS, new neutron objects were implemented:

* QosPolicy: directly maps to the conceptual policy resource, as defined above.
* QosBandwidthLimitRule: class that represents the only rule type supported by
  initial QoS design.

Those are defined in:

* neutron.objects.qos.policy
* neutron.objects.qos.rule

For QosPolicy neutron object, the following public methods were implemented:

* get_network_policy/get_port_policy: returns a policy object that is attached
  to the corresponding Neutron resource.
* attach_network/attach_port: attach a policy to the corresponding Neutron
  resource.
* detach_network/detach_port: detach a policy from the corresponding Neutron
  resource.

In addition to the fields that belong to QoS policy database object itself,
synthetic fields were added to the object that represent lists of rules that
belong to the policy. To get a list of all rules for a specific policy, a
consumer of the object can just access the corresponding attribute via:

* policy.rules

Implementation is done in a way that will allow adding a new rule list field
with little or no modifications in the policy object itself. This is achieved
by smart introspection of existing available rule object definitions and
automatic definition of those fields on the policy class.

Note that rules are loaded in a non lazy way, meaning they are all fetched from
the database on policy fetch.

For Qos<type>Rule objects, an extendable approach was taken to allow easy
addition of objects for new rule types. To accommodate this, fields common to
all types are put into a base class called QosRule that is then inherited into
type-specific rule implementations that, ideally, only define additional fields
and some other minor things.

Note that the QosRule base class is not registered with oslo.versionedobjects
registry, because it's not expected that 'generic' rules should be
instantiated (and to suggest just that, the base rule class is marked as ABC).

QoS objects rely on some primitive database API functions that are added in:

* neutron.db.api: those can be reused to fetch other models that do not have
  corresponding versioned objects yet, if needed.
* neutron.db.qos.api: contains database functions that are specific to QoS
  models.


RPC communication
~~~~~~~~~~~~~~~~~

Details on RPC communication implemented in reference backend driver are
discussed in `a separate page <rpc_callbacks.html>`_.

One thing that should be mentioned here explicitly is that RPC callback
endpoints communicate using real versioned objects (as defined by serialization
for oslo.versionedobjects library), not vague json dictionaries. Meaning,
oslo.versionedobjects are on the wire and not just used internally inside a
component.

One more thing to note is that though RPC interface relies on versioned
objects, it does not yet rely on versioning features the oslo.versionedobjects
library provides. This is because Liberty is the first release where we start
using the RPC interface, so we have no way to get different versions in a
cluster. That said, the versioning strategy for QoS is thought through and
described in `the separate page <rpc_callbacks.html>`_.

There is expectation that after RPC callbacks are introduced in Neutron, we
will be able to migrate propagation from server to agents for other resources
(f.e. security groups) to the new mechanism. This will need to wait until those
resources get proper NeutronObject implementations.

The flow of updates is as follows:

* if a port that is bound to the agent is attached to a QoS policy, then ML2
  plugin detects the change by relying on ML2 QoS extension driver, and
  notifies the agent about a port change. The agent proceeds with the
  notification by calling to get_device_details() and getting the new port dict
  that contains a new qos_policy_id. Each device details dict is passed into l2
  agent extension manager that passes it down into every enabled extension,
  including QoS. QoS extension sees that there is a new unknown QoS policy for
  a port, so it uses ResourcesPullRpcApi to fetch the current state of the
  policy (with all the rules included) from the server. After that, the QoS
  extension applies the rules by calling into QoS driver that corresponds to
  the agent.
* on existing QoS policy update (it includes any policy or its rules change),
  server pushes the new policy object state through ResourcesPushRpcApi
  interface. The interface fans out the serialized (dehydrated) object to any
  agent that is listening for QoS policy updates. If an agent have seen the
  policy before (it is attached to one of the ports it maintains), then it goes
  with applying the updates to the port. Otherwise, the agent silently ignores
  the update.


Agent side design
-----------------

To ease code reusability between agents and to avoid the need to patch an agent
for each new core resource extension, pluggable L2 agent extensions were
introduced. They can be especially interesting to third parties that don't want
to maintain their code in Neutron tree.

Extensions are meant to receive handle_port events, and do whatever they need
with them.

* neutron.agent.l2.agent_extension:
  This module defines an abstract extension interface.

* neutron.agent.l2.extensions.manager:
  This module contains a manager that allows to register multiple extensions,
  and passes handle_port events down to all enabled extensions.

* neutron.agent.l2.extensions.qos
  defines QoS L2 agent extension. It receives handle_port and delete_port
  events and passes them down into QoS agent backend driver (see below). The
  file also defines the QosAgentDriver interface. Note: each backend implements
  its own driver. The driver handles low level interaction with the underlying
  networking technology, while the QoS extension handles operations that are
  common to all agents.


Agent backends
~~~~~~~~~~~~~~

At the moment, QoS is supported by Open vSwitch, SR-IOV and Linux bridge
ml2 drivers.

Each agent backend defines a QoS driver that implements the QosAgentDriver
interface:

* Open vSwitch (QosOVSAgentDriver);
* SR-IOV (QosSRIOVAgentDriver);
* Linux bridge (QosLinuxbridgeAgentDriver).


Open vSwitch
++++++++++++

Open vSwitch implementation relies on the new ovs_lib OVSBridge functions:

* get_egress_bw_limit_for_port
* create_egress_bw_limit_for_port
* delete_egress_bw_limit_for_port

An egress bandwidth limit is effectively configured on the port by setting
the port Interface parameters ingress_policing_rate and
ingress_policing_burst.

That approach is less flexible than linux-htb, Queues and OvS QoS profiles,
which we may explore in the future, but which will need to be used in
combination with openflow rules.

SR-IOV
++++++

SR-IOV bandwidth limit implementation relies on the new pci_lib function:

* set_vf_max_rate

As the name of the function suggests, the limit is applied on a Virtual
Function (VF).

ip link interface has the following limitation for bandwidth limit: it uses
Mbps as units of bandwidth measurement, not kbps, and does not support float
numbers. So in case the limit is set to something less than 1000 kbps, it's set
to 1 Mbps only. If the limit is set to something that does not divide to 1000
kbps chunks, then the effective limit is rounded to the nearest integer Mbps
value.

Linux bridge
~~~~~~~~~~~~

The Linux bridge implementation relies on the new tc_lib functions:

* set_bw_limit
* update_bw_limit
* delete_bw_limit

The ingress bandwidth limit is configured on the tap port by setting a simple
`tc-tbf <http://linux.die.net/man/8/tc-tbf>`_ queueing discipline (qdisc) on the
port. It requires a value of HZ parameter configured in kernel on the host.
This value is neccessary to calculate the minimal burst value which is set in
tc. Details about how it is calculated can be found in
`http://unix.stackexchange.com/a/100797`_. This solution is similar to Open
vSwitch implementation.

Configuration
-------------

To enable the service, the following steps should be followed:

On server side:

* enable qos service in service_plugins;
* set the needed notification_drivers in [qos] section (message_queue is the default);
* for ml2, add 'qos' to extension_drivers in [ml2] section.

On agent side (OVS):

* add 'qos' to extensions in [agent] section.


Testing strategy
----------------

All the code added or extended as part of the effort got reasonable unit test
coverage.


Neutron objects
~~~~~~~~~~~~~~~

Base unit test classes to validate neutron objects were implemented in a way
that allows code reuse when introducing a new object type.

There are two test classes that are utilized for that:

* BaseObjectIfaceTestCase: class to validate basic object operations (mostly
  CRUD) with database layer isolated.
* BaseDbObjectTestCase: class to validate the same operations with models in
  place and database layer unmocked.

Every new object implemented on top of one of those classes is expected to
either inherit existing test cases as is, or reimplement it, if it makes sense
in terms of how those objects are implemented. Specific test classes can
obviously extend the set of test cases as they see needed (f.e. you need to
define new test cases for those additional methods that you may add to your
object implementations on top of base semantics common to all neutron objects).


Functional tests
~~~~~~~~~~~~~~~~

Additions to ovs_lib to set bandwidth limits on ports are covered in:

* neutron.tests.functional.agent.test_ovs_lib


New functional tests for tc_lib to set bandwidth limits on ports are in:

* neutron.tests.functional.agent.linux.test_tc_lib


API tests
~~~~~~~~~

API tests for basic CRUD operations for ports, networks, policies, and rules were added in:

* neutron.tests.api.test_qos
