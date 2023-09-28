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


.. _rpc_callbacks:

RPC Messaging Callback System
=============================

Neutron already has a `callback system
<https://docs.openstack.org/neutron-lib/latest/contributor/callbacks.html>`_
for in-process resource callbacks where publishers and subscribers are
able to publish and subscribe for resource events.

This system is different, and is intended to be used for inter-process
callbacks, via the messaging fanout mechanisms.

In Neutron, agents may need to subscribe to specific resource details which
may change over time. And the purpose of this messaging callback system
is to allow agent subscription to those resources without the need to extend
modify existing RPC calls, or creating new RPC messages.

A few resource which can benefit of this system:

* QoS policies;
* Security Groups.

Using a remote publisher/subscriber pattern, the information about such
resources could be published using fanout messages to all interested nodes,
minimizing messaging requests from agents to server since the agents
get subscribed for their whole lifecycle (unless they unsubscribe).

Within an agent, there could be multiple subscriber callbacks to the same
resource events, the resources updates would be dispatched to the subscriber
callbacks from a single message. Any update would come in a single message,
doing only a single oslo versioned objects deserialization on each receiving
agent.

This publishing/subscription mechanism is highly dependent on the format
of the resources passed around. This is why the library only allows
versioned objects to be published and subscribed. Oslo versioned objects
allow object version down/up conversion. [#vo_mkcompat]_ [#vo_mkcptests]_

For the VO's versioning schema look here: [#vo_versioning]_

versioned_objects serialization/deserialization with the
obj_to_primitive(target_version=..) and primitive_to_obj() [#ov_serdes]_
methods is used internally to convert/retrieve objects before/after messaging.

Serialized versioned objects look like::

   {'versioned_object.version': '1.0',
    'versioned_object.name': 'QoSPolicy',
    'versioned_object.data': {'rules': [
                                        {'versioned_object.version': '1.0',
                                         'versioned_object.name': 'QoSBandwidthLimitRule',
                                         'versioned_object.data': {'name': u'a'},
                                         'versioned_object.namespace': 'versionedobjects'}
                                        ],
                              'uuid': u'abcde',
                              'name': u'aaa'},
    'versioned_object.namespace': 'versionedobjects'}

Rolling upgrades strategy
-------------------------
In this section we assume the standard Neutron upgrade process, which means
upgrade the server first and then upgrade the agents:

:doc:`More information about the upgrade strategy <upgrade>`.

We provide an automatic method which avoids manual pinning and unpinning
of versions by the administrator which could be prone to error.

Resource pull requests
~~~~~~~~~~~~~~~~~~~~~~
Resource pull requests will always be ok because the underlying resource RPC
does provide the version of the requested resource id  / ids. The server will
be upgraded first, so it will always be able to satisfy any version the agents
request.

Resource push notifications
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Agents will subscribe to the neutron-vo-<resource_type>-<version> fanout queue
which carries updated objects for the version they know about. The versions
they know about depend on the runtime Neutron versioned objects they started with.

When the server upgrades, it should be able to instantly calculate a census of
agent versions per object (we will define a mechanism for this in a later
section). It will use the census to send fanout messages on all the version
span a resource type has.

For example, if neutron-server knew it has rpc-callback aware agents with
versions 1.0, and versions 1.2 of resource type "A", any update would be sent
to neutron-vo-A_1.0 and neutron-vo-A_1.2.

TODO(mangelajo): Verify that after upgrade is finished any unused messaging
resources (queues, exchanges, and so on) are released as older agents go away
and neutron-server stops producing new message casts. Otherwise document the
need for a neutron-server restart after rolling upgrade has finished if we
want the queues cleaned up.


Leveraging agent state reports for object version discovery
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
We add a row to the agent db for tracking agent known objects and version
numbers. This resembles the implementation of the configuration column.

Agents report at start not only their configuration now, but also
their subscribed object type / version pairs, that are stored in the
database and made available to any neutron-server requesting it::

    'resource_versions': {'QosPolicy': '1.1',
                          'SecurityGroup': '1.0',
                          'Port': '1.0'}

There was a subset of Liberty agents depending on QosPolicy that required
'QosPolicy': '1.0' if the qos plugin is installed. We were able to identify
those by the binary name (included in the report):

* 'neutron-openvswitch-agent'
* 'neutron-sriov-nic-agent'

This transition was handled in the Mitaka version, but it's not handled
anymore in Newton, since only one major version step upgrades are supported.

Version discovery
+++++++++++++++++
With the above mechanism in place and considering the exception of
neutron-openvswitch-agent and neutron-sriov-agent requiring QoSpolicy 1.0,
we discover the subset of versions to be sent on every push notification.

Agents that are in down state are excluded from this calculation.
We use an extended timeout for agents in this calculation to make sure
we're on the safe side, specially if deployer marked agents with low
timeouts.

Starting at Mitaka, any agent interested in versioned objects via this API
should report their resource/version tuples of interest (the resource type/
version pairs they're subscribed to).

The plugins interested in this RPC mechanism must inherit AgentDbMixin,
since this mechanism is only intended to be used from agents at the moment,
while it could be extended to be consumed from other components if necessary.

The AgentDbMixin provides::

   def get_agents_resource_versions(self, tracker):
      ...

Caching mechanism
'''''''''''''''''
The version subset per object is cached to avoid DB requests on every push
given that we assume that all old agents are already registered at the time of
upgrade.

Cached subset is re-evaluated (to cut down the version sets as agents
upgrade) after neutron.api.rpc.callbacks.version_manager.VERSIONS_TTL.

As a fast path to update this cache on all neutron-servers when upgraded agents
come up (or old agents revive after a long timeout or even a downgrade) the
server registering the new status update notifies the other servers about
the new consumer resource versions via cast.

All notifications for all calculated version sets must be sent, as non-upgraded
agents would otherwise not receive them.

It is safe to send notifications to any fanout queue as they will be discarded
if no agent is listening.

Topic names for every resource type RPC endpoint
------------------------------------------------

neutron-vo-<resource_class_name>-<version>

In the future, we may want to get oslo messaging to support subscribing
topics dynamically, then we may want to use:

neutron-vo-<resource_class_name>-<resource_id>-<version> instead,

or something equivalent which would allow fine granularity for the receivers
to only get interesting information to them.

Subscribing to resources
------------------------

Imagine that you have agent A, which just got to handle a new port, which
has an associated security group, and QoS policy.

The agent code processing port updates may look like::

    from neutron.api.rpc.callbacks.consumer import registry
    from neutron.api.rpc.callbacks import events
    from neutron.api.rpc.callbacks import resources


    def process_resource_updates(context, resource_type, resource_list, event_type):

        # send to the right handler which will update any control plane
        # details related to the updated resources...


    def subscribe_resources():
        registry.register(process_resource_updates, resources.SEC_GROUP)

        registry.register(process_resource_updates, resources.QOS_POLICY)

    def port_update(port):

        # here we extract sg_id and qos_policy_id from port..

        sec_group = registry.pull(resources.SEC_GROUP, sg_id)
        qos_policy = registry.pull(resources.QOS_POLICY, qos_policy_id)


The relevant function is:

* register(callback, resource_type): subscribes callback to a resource type.


The callback function will receive the following arguments:

* context: the neutron context that triggered the notification.
* resource_type: the type of resource which is receiving the update.
* resource_list: list of resources which have been pushed by server.
* event_type: will be one of CREATED, UPDATED, or DELETED, see
  neutron.api.rpc.callbacks.events for details.

With the underlying oslo_messaging support for dynamic topics on the receiver
we cannot implement a per "resource type + resource id" topic, rabbitmq seems
to handle 10000's of topics without suffering, but creating 100's of
oslo_messaging receivers on different topics seems to crash.

We may want to look into that later, to avoid agents receiving resource updates
which are uninteresting to them.

Unsubscribing from resources
----------------------------

To unsubscribe registered callbacks:

* unsubscribe(callback, resource_type): unsubscribe from specific resource type.
* unsubscribe_all(): unsubscribe from all resources.


Sending resource events
-----------------------

On the server side, resource updates could come from anywhere, a service plugin,
an extension, anything that updates, creates, or destroys the resources and that
is of any interest to subscribed agents.

A callback is expected to receive a list of resources. When resources in the list
belong to the same resource type, a single push RPC message is sent; if the list
contains objects of different resource types, resources of each type are grouped
and sent separately, one push RPC message per type. On the receiver side,
resources in a list always belong to the same type. In other words, a server-side
push of a list of heterogeneous objects will result into N messages on bus and
N client-side callback invocations, where N is the number of unique resource
types in the given list, e.g. L(A, A, B, C, C, C) would be fragmented into
L1(A, A), L2(B), L3(C, C, C), and each list pushed separately.

Note: there is no guarantee in terms of order in which separate resource lists
will be delivered to consumers.

The server/publisher side may look like::

    from neutron.api.rpc.callbacks.producer import registry
    from neutron.api.rpc.callbacks import events

    def create_qos_policy(...):
        policy = fetch_policy(...)
        update_the_db(...)
        registry.push([policy], events.CREATED)

    def update_qos_policy(...):
        policy = fetch_policy(...)
        update_the_db(...)
        registry.push([policy], events.UPDATED)

    def delete_qos_policy(...):
        policy = fetch_policy(...)
        update_the_db(...)
        registry.push([policy], events.DELETED)


References
----------
.. [#ov_serdes] https://github.com/openstack/oslo.versionedobjects/blob/ce00f18f7e9143b5175e889970564813189e3e6d/oslo_versionedobjects/tests/test_objects.py#L410
.. [#vo_mkcompat] https://github.com/openstack/oslo.versionedobjects/blob/ce00f18f7e9143b5175e889970564813189e3e6d/oslo_versionedobjects/base.py#L474
.. [#vo_mkcptests] https://github.com/openstack/oslo.versionedobjects/blob/ce00f18f7e9143b5175e889970564813189e3e6d/oslo_versionedobjects/tests/test_objects.py#L114
.. [#vo_versioning] https://github.com/openstack/oslo.versionedobjects/blob/ce00f18f7e9143b5175e889970564813189e3e6d/oslo_versionedobjects/base.py#L248
