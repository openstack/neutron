==================
Quality of Service
==================

Quality of Service advanced service is designed as a service plugin. The
service is decoupled from the rest of Neutron code on multiple levels (see
below).

QoS is the first service/api extension to extend core resources (ports,
networks) without using mixins inherited from plugins.

Details about the DB models, API extension, and use cases can be found here: `qos spec <http://specs.openstack.org/openstack/neutron-specs/specs/liberty/qos-api-extension.html>`_
.

Service side design
===================
* neutron.extensions.qos:
  base extension + API controller definition.

* neutron.services.qos.qos_plugin:
  QoSPlugin, service plugin that implements 'qos' extension, receiving and
  handling API calls to create/modify policies and rules. It also handles core
  plugin requests to associate ports and networks with a QoS policy.

* neutron.services.qos.drivers.qos_base:
  the interface class for server-side QoS backend which will receive {create,
  update, delete} events on any rule change.

* neutron.services.qos.drivers.rpc.mq_qos:
  message queue based reference backend driver which provides messaging
  notifications to any interested agent, using `RPC callbacks <rpc_callbacks.html>`_.


Supported QoS rule types
------------------------

Any plugin or Ml2 mechanism driver can claim support for some QoS rule types by
providing a plugin/driver class property called 'supported_qos_rule_types' that
should return a list of strings that correspond to QoS rule types (for the list
of all rule types, see: neutron.extensions.qos.VALID_RULE_TYPES).

In the most simple case, the property can be represented by a simple Python
list defined on the class.

For Ml2 plugin, the list of supported QoS rule types is defined as a common
subset of rules supported by all active mechanism drivers.

Note: the list of supported rule types reported by core plugin is not enforced
when accessing QoS rule resources. This is mostly because then we would not be
able to create any rules while at least one ml2 driver in gate lacks support
for QoS (at the moment of writing, linuxbridge is such a driver).


QoS resources
-------------

QoS design defines the following two conceptual resources to define QoS rules
for a port or a network:

* QoS policy
* QoS rule (type specific)

Each QoS policy contains zero or more QoS rules. A policy is then applied to a
network or a port, making all rules of the policy applied to the corresponding
Neutron resource (for a network, applying a policy means that the policy will
be applied to all ports that belong to it).

From database point of view, following objects are defined in schema:

* QosPolicy: directly maps to the conceptual policy resource.
* QosNetworkPolicyBinding, QosPortPolicyBinding: defines attachment between a
  Neutron resource and a QoS policy.
* QosBandwidthLimitRule: defines the only rule type available at the moment.


All database models are defined under:

* neutron.db.qos.models

There is a long history of passing database dictionaries directly into business
logic of Neutron. This path is not the one we wanted to take for QoS effort, so
we've also introduced a new objects middleware to encapsulate the database logic
from the rest of the Neutron code that works with QoS resources. For this, we've
adopted oslo.versionedobjects library and introduced a new NeutronObject class
that is a base for all other objects that will belong to the middle layer.
There is an expectation that Neutron will evolve into using objects for all
resources it handles, though that part is obviously out of scope for the QoS
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
addition of objects for new rule types. To accomodate this, fields common to
all types are put into a base class called QosRule that is then inherited into
type-specific rule implementations that, ideally, only define additional fields
and some other minor things.

Note that the QosRule base class is not registered with oslo.versionedobjects
registry, because it's not expected that 'generic' rules should be
instantiated (and to enforce just that, the base rule class is marked as ABC).

QoS objects rely on some primitive database API functions that are added in:

* neutron.db.api
* neutron.db.qos.api


Callback changes
----------------

TODO(QoS): We're changing strategy here to not rely on AFTER_READ callbacks,
           and foster discussion about how to do decouple core resource
           extension in the community. So, update next phrase when that
           happens.

To extend ports and networks with qos_policy_id field, AFTER_READ callback
event is introduced.

Note: a better mechanism is being built by @armax to make resource extensions
more explicit and under control. We will migrate to that better mechanism as
soon as it's available.


RPC communication
-----------------
Details on RPC communication implemented in reference backend driver are
discussed in `a separate page <rpc_callbacks.html>`_.

One thing that should be mentioned here explicitly is that RPC callback
endpoints communicate using real versioned objects (as defined by serialization
for oslo.versionedobjects library), not vague json dictionaries. Meaning,
oslo.versionedobjects are on the wire and not just used internally inside a
component.

There is expectation that after RPC callbacks are introduced in Neutron, we
will be able to migrate propagation from server to agents for other resources
(f.e. security groups) to the new mechanism. This will need to wait until those
resources get proper NeutronObject implementations.


Agent side design
=================

To facilitate code reusability between agents and agent extensions without
patching the agent code itself, agent extensions were introduced. They can be
especially interesting to third parties that don't want to maintain their code
in Neutron tree.

Extensions are meant to receive basic events like port update or delete, and do
whatever they need with it.

* neutron.agent.l2.agent_extension:
  extension interface definition.

* neutron.agent.l2.agent_extensions_manager:
  manager that allows to register multiple extensions, and pass events down to
  all enabled extensions.

* neutron.agent.l2.extensions.qos_agent:
  defines QoSAgentExtension that is also pluggable using QoSAgentDriver
  implementations that are specific to agent backends being used.

* neutron.agent.l2.l2_agent:
  provides the API entry point for process_{network,subnet,port}_extension,
  and holds an agent extension manager inside.
  TODO(QoS): clarify what this is for, I don't follow a bit.


ML2
---

TODO(QoS): there is work ongoing that will need to be reflected here.


Agent backends
--------------

TODO(QoS): this section needs rework.

Open vSwitch

* neutron.plugins.ml2.drivers.openvswitch.agent.extension_drivers.qos_driver
  This module implements the QoSAgentDriver interface used by the
  QosAgentExtension.

* neutron.agent.common.ovs_lib
* neutron.agent.ovsdb.api
* neutron.agent.ovsdb.impl_idl
* neutron.agent.ovsdb.impl_vsctl
* neutron.agent.ovsdb.native.commands

SR-IOV


Configuration
=============

TODO(QoS)


Testing strategy
================

Neutron objects
---------------

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
