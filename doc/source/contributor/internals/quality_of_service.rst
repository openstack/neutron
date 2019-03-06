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

* neutron.extensions.qos_fip:
  base extension + API controller definition. Adds qos_policy_id to floating
  IP, enabling users to set/update the binding QoS policy of a floating IP.

* neutron.services.qos.qos_plugin:
  QoSPlugin, service plugin that implements 'qos' extension, receiving and
  handling API calls to create/modify policies and rules.

* neutron.services.qos.drivers.manager:
  the manager that passes object actions down to every enabled QoS driver and
  issues RPC calls when any of the drivers require RPC push notifications.

* neutron.services.qos.drivers.base:
  the interface class for pluggable QoS drivers that are used to update
  backends about new {create, update, delete} events on any rule or policy
  change, including precommit events that some backends could need for
  synchronization reason. The drivers also declare which QoS rules,
  VIF drivers and VNIC types are supported.

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


QoS plugin implementation guide
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The neutron.extensions.qos.QoSPluginBase class uses method proxies for methods
relating to QoS policy rules. Each of these such methods is generic in the sense
that it is intended to handle any rule type. For example, QoSPluginBase has a
create_policy_rule method instead of both create_policy_dscp_marking_rule and
create_policy_bandwidth_limit_rule methods. The logic behind the proxies allows
a call to a plugin's create_policy_dscp_marking_rule to be handled by the
create_policy_rule method, which will receive a QosDscpMarkingRule object as an
argument in order to execute behavior specific to the DSCP marking rule type.
This approach allows new rule types to be introduced without requiring a plugin
to modify code as a result. As would be expected, any subclass of QoSPluginBase
must override the base class's abc.abstractmethod methods, even if to raise
NotImplemented.


Supported QoS rule types
~~~~~~~~~~~~~~~~~~~~~~~~

Each QoS driver has a property called supported_rule_types, where the driver
exposes the rules it's able to handle.

For a list of all rule types, see:
neutron.services.qos.qos_consts.VALID_RULE_TYPES.

The list of supported QoS rule types exposed by neutron is calculated as
the common subset of rules supported by all active QoS drivers.

Note: the list of supported rule types reported by core plugin is not enforced
when accessing QoS rule resources. This is mostly because then we would not be
able to create rules while at least one of the QoS driver in gate lacks
support for the rules we're trying to test.


Database models
~~~~~~~~~~~~~~~

QoS design defines the following two conceptual resources to apply QoS rules
for a port, a network or a floating IP:

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

Each project can have at most one default QoS policy, although is not
mandatory. If a default QoS policy is defined, all new networks created within
this project will have assigned this policy, as long as no other QoS policy is
explicitly attached during the creation process. If the default QoS policy is
unset, no change to existing networks will be made.

From database point of view, following objects are defined in schema:

* QosPolicy: directly maps to the conceptual policy resource.
* QosNetworkPolicyBinding, QosPortPolicyBinding, QosFIPPolicyBinding:
  define attachment between a Neutron resource and a QoS policy.
* QosPolicyDefault: defines a default QoS policy per project.
* QosBandwidthLimitRule: defines the rule to limit the maximum egress
  bandwidth.
* QosDscpMarkingRule: defines the rule that marks the Differentiated Service
  bits for egress traffic.
* QosMinimumBandwidthRule: defines the rule that creates a minimum bandwidth
  constraint.

All database models are defined under:

* neutron.db.qos.models


QoS versioned objects
~~~~~~~~~~~~~~~~~~~~~

For QoS, the following neutron objects are implemented:

* QosPolicy: directly maps to the conceptual policy resource, as defined above.
* QosPolicyDefault: defines a default QoS policy per project.
* QosBandwidthLimitRule: defines the instance bandwidth limit rule type,
  characterized by a max kbps and a max burst kbits. This rule has also a
  direction parameter to set the traffic direction, from the instance's point of view.
* QosDscpMarkingRule: defines the DSCP rule type, characterized by an even integer
  between 0 and 56.  These integers are the result of the bits in the DiffServ section
  of the IP header, and only certain configurations are valid.  As a result, the list
  of valid DSCP rule types is: 0, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32,
  34, 36, 38, 40, 46, 48, and 56.
* QosMinimumBandwidthRule: defines the minimum assured bandwidth rule type,
  characterized by a min_kbps parameter. This rule has also a direction
  parameter to set the traffic direction, from the instance point of view. The
  only direction now implemented is egress.

Those are defined in:

* neutron.objects.qos.policy
* neutron.objects.qos.rule

For QosPolicy neutron object, the following public methods were implemented:

* get_network_policy/get_port_policy/get_fip_policy: returns a policy object
  that is attached to the corresponding Neutron resource.
* attach_network/attach_port/attach_floatingip: attach a policy to the
  corresponding Neutron resource.
* detach_network/detach_port/detach_floatingip: detach a policy from the
  corresponding Neutron resource.

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

* neutron_lib.db.api: those can be reused to fetch other models that do not have
  corresponding versioned objects yet, if needed.
* neutron.db.qos.api: contains database functions that are specific to QoS
  models.


RPC communication
~~~~~~~~~~~~~~~~~

Details on RPC communication implemented in reference backend driver are
discussed in `a separate page <rpc_callbacks.html>`_.

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
* For floating IPs, a ``fip_qos`` L3 agent extension was implemented. This
  extension receives and processes router updates. For each update, it goes
  over each floating IP associated to the router. If a floating IP has a QoS
  policy associated to it, the extension uses ResourcesPullRpcApi to fetch
  the policy details from the Neutron server. If the policy includes
  ``bandwidth_limit`` rules, the extension applies them to the appropriate
  router device by directly calling the l3_tc_lib.
* on existing QoS policy update (it includes any policy or its rules change),
  server pushes the new policy object state through ResourcesPushRpcApi
  interface. The interface fans out the serialized (dehydrated) object to any
  agent that is listening for QoS policy updates. If an agent have seen the
  policy before (it is attached to one of the ports/floating IPs it maintains),
  then it goes with applying the updates to the port/floating IP. Otherwise,
  the agent silently ignores the update.


Agent side design
-----------------

Reference agents implement QoS functionality using an `L2 agent extension
<./l2_agent_extensions.html>`_.

* neutron.agent.l2.extensions.qos
  defines QoS L2 agent extension. It receives handle_port and delete_port
  events and passes them down into QoS agent backend driver (see below). The
  file also defines the QosAgentDriver interface. Note: each backend implements
  its own driver. The driver handles low level interaction with the underlying
  networking technology, while the QoS extension handles operations that are
  common to all agents.

For L3 agent:

* neutron.agent.l3.extensions.fip_qos
  defines QoS L3 agent extension. It implements the L3 agent side of floating
  IP rate limit. For all routers, if floating IP has QoS ``bandwidth_limit``
  rules, the corresponding TC filters will be added to the appropriate router
  device, depending on the router type.


Agent backends
~~~~~~~~~~~~~~

At the moment, QoS is supported by Open vSwitch, SR-IOV and Linux bridge
ml2 drivers.

Each agent backend defines a QoS driver that implements the QosAgentDriver
interface:

* Open vSwitch (QosOVSAgentDriver);
* SR-IOV (QosSRIOVAgentDriver);
* Linux bridge (QosLinuxbridgeAgentDriver).

Table of Neutron backends, supported rules and traffic direction (from the VM
point of view)
::

    +----------------------+--------------------+--------------------+--------------------+
    | Rule \ Backend       | Open vSwitch       | SR-IOV             | Linux Bridge       |
    +----------------------+--------------------+--------------------+--------------------+
    | Bandwidth Limit      | Egress/Ingress     | Egress (1)         | Egress/Ingress     |
    +----------------------+--------------------+--------------------+--------------------+
    | Minimum Bandwidth    | Egress/Ingress (2) | Egress/Ingress (2) | -                  |
    +----------------------+--------------------+--------------------+--------------------+
    | DSCP Marking         | Egress             | -                  | Egress             |
    +----------------------+--------------------+--------------------+--------------------+

    (1) Max burst parameter is skipped because it's not supported by ip tool.
    (2) Placement based enforcement works for both egress and ingress directions,
        but dataplane enforcement depends on the backend.

Table of Neutron backends, supported directions and enforcement types for
Minimum Bandwidth rule
::

    +----------------------------+----------------+----------------+----------------+
    | Enforcement type \ Backend | Open vSwitch   | SR-IOV         | Linux Bridge   |
    +----------------------------+----------------+----------------+----------------+
    | Dataplane                  | -              | Egress         | -              |
    |                            |                | (Newton+)      |                |
    +----------------------------+----------------+----------------+----------------+
    | Placement                  | Egress/Ingress | Egress/Ingress | -              |
    |                            | (Stein+)       | (Stein+)       |                |
    +----------------------------+----------------+----------------+----------------+


Open vSwitch
++++++++++++

Open vSwitch implementation relies on the new ovs_lib OVSBridge functions:

* get_egress_bw_limit_for_port
* create_egress_bw_limit_for_port
* delete_egress_bw_limit_for_port
* get_ingress_bw_limit_for_port
* update_ingress_bw_limit_for_port
* delete_ingress_bw_limit_for_port

An egress bandwidth limit is effectively configured on the port by setting
the port Interface parameters ingress_policing_rate and
ingress_policing_burst.

That approach is less flexible than linux-htb, Queues and OvS QoS profiles,
which we may explore in the future, but which will need to be used in
combination with openflow rules.

An ingress bandwidth limit is effectively configured on the port by setting
Queue and OvS QoS profile with linux-htb type for port.

The Open vSwitch DSCP marking implementation relies on the recent addition
of the ovs_agent_extension_api OVSAgentExtensionAPI to request access to the
integration bridge functions:

* add_flow
* mod_flow
* delete_flows
* dump_flows_for

The DSCP markings are in fact configured on the port by means of
openflow rules.

SR-IOV
++++++

SR-IOV bandwidth limit and minimum bandwidth implementation relies on the
new pci_lib function:

* set_vf_rate

As the name of the function suggests, the limit is applied on a Virtual
Function (VF). This function has a parameter called "rate_type" and
its value can be set to "rate" or "min_tx_rate", which is for enforcing
bandwidth limit or minimum bandwidth respectively.

ip link interface has the following limitation for bandwidth limit: it uses
Mbps as units of bandwidth measurement, not kbps, and does not support float
numbers. So in case the limit is set to something less than 1000 kbps, it's set
to 1 Mbps only. If the limit is set to something that does not divide to 1000
kbps chunks, then the effective limit is rounded to the nearest integer Mbps
value.

Linux bridge
~~~~~~~~~~~~

The Linux bridge implementation relies on the new tc_lib functions.

For egress bandwidth limit rule:

* set_filters_bw_limit
* update_filters_bw_limit
* delete_filters_bw_limit

The egress bandwidth limit is configured on the tap port by setting traffic
policing on tc ingress queueing discipline (qdisc). Details about ingress
qdisc can be found on `lartc how-to <http://lartc.org/howto/lartc.adv-qdisc.ingress.html>`__.
The reason why ingress qdisc is used to configure egress bandwidth limit is that
tc is working on traffic which is visible from "inside bridge" perspective. So
traffic incoming to bridge via tap interface is in fact outgoing from Neutron's
port.
This implementation is the same as what Open vSwitch is doing when
ingress_policing_rate and ingress_policing_burst are set for port.

For ingress bandwidth limit rule:

* set_tbf_bw_limit
* update_tbf_bw_limit
* delete_tbf_bw_limit

The ingress bandwidth limit is configured on the tap port by setting a simple
`tc-tbf <http://linux.die.net/man/8/tc-tbf>`_ queueing discipline (qdisc) on the
port. It requires a value of HZ parameter configured in kernel on the host.
This value is necessary to calculate the minimal burst value which is set in
tc. Details about how it is calculated can be found in
`here <http://unix.stackexchange.com/a/100797>`_. This solution is similar to Open
vSwitch implementation.

The Linux bridge DSCP marking implementation relies on the
linuxbridge_extension_api to request access to the IptablesManager class
and to manage chains in the ``mangle`` table in iptables.

QoS driver design
-----------------

QoS framework is flexible enough to support any third-party vendor. To integrate a
third party driver (that just wants to be aware of the QoS create/update/delete API
calls), one needs to implement 'neutron.services.qos.drivers.base', and register
the driver during the core plugin or mechanism driver load, see

neutron.services.qos.drivers.openvswitch.driver register method for an example.

.. note::
 All the functionality MUST be implemented by the vendor, neutron's QoS framework
 will just act as an interface to bypass the received QoS API request and help with
 database persistence for the API operations.

.. note::
 L3 agent ``fip_qos`` extension does not have a driver implementation,
 it directly uses the ``l3_tc_lib`` for all types of routers.

Configuration
-------------

To enable the service, the following steps should be followed:

On server side:

* enable qos service in service_plugins;
* for ml2, add 'qos' to extension_drivers in [ml2] section;
* for L3 floating IP QoS, add 'qos' and 'router' to service_plugins.

On agent side (OVS):

* add 'qos' to extensions in [agent] section.

On L3 agent side:

* For for floating IPs QoS support, add 'fip_qos' to extensions in [agent] section.


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


New functional tests for test_l3_tc_lib to set TC filters on router floating
IP related device are covered in:

* neutron.tests.functional.agent.linux.test_l3_tc_lib

New functional tests for L3 agent floating IP rate limit:

* neutron.tests.functional.agent.l3.extensions.test_fip_qos_extension


API tests
~~~~~~~~~

API tests for basic CRUD operations for ports, networks, policies, and rules were added in:

* neutron-tempest-plugin.api.test_qos
