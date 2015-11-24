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

Neutron Messaging Callback System
=================================

Neutron already has a :doc:`callback system <callbacks>` for
in-process resource callbacks where publishers and subscribers are able
to publish and subscribe for resource events.

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

Considering rolling upgrades, there are several scenarios to look at:

* publisher (generally neutron-server or a service) and subscriber (agent)
  know the same version of the objects, so they serialize, and deserialize
  without issues.

* publisher knows (and sends) an older version of the object, subscriber
  will get the object updated to latest version on arrival before any
  callback is called.

* publisher sends a newer version of the object, subscriber won't be able
  to deserialize the object, in this case (PLEASE DISCUSS), we can think of two
  strategies:


The strategy for upgrades will be:
   During upgrades, we pin neutron-server to a compatible version for resource
   fanout updates, and the server sends both the old, and the newer version.
   The new agents process updates, taking the newer version of the resource
   fanout updates.  When the whole system upgraded, we un-pin the compatible
   version fanout.

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


    def process_resource_updates(resource_type, resource, event_type):

        # send to the right handler which will update any control plane
        # details related to the updated resource...


    def subscribe_resources():
        registry.subscribe(process_resource_updates, resources.SEC_GROUP)

        registry.subscribe(process_resource_updates, resources.QOS_POLICY)

    def port_update(port):

        # here we extract sg_id and qos_policy_id from port..

        sec_group = registry.pull(resources.SEC_GROUP, sg_id)
        qos_policy = registry.pull(resources.QOS_POLICY, qos_policy_id)


The relevant function is:

* subscribe(callback, resource_type): subscribes callback to a resource type.


The callback function will receive the following arguments:

* resource_type: the type of resource which is receiving the update.
* resource: resource of supported object
* event_type: will be one of CREATED, UPDATED, or DELETED, see
  neutron.api.rpc.callbacks.events for details.

With the underlaying oslo_messaging support for dynamic topics on the receiver
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
an extension, anything that updates, creates, or destroys the resource and that
is of any interest to subscribed agents.

The server/publisher side may look like::

    from neutron.api.rpc.callbacks.producer import registry
    from neutron.api.rpc.callbacks import events

    def create_qos_policy(...):
        policy = fetch_policy(...)
        update_the_db(...)
        registry.push(policy, events.CREATED)

    def update_qos_policy(...):
        policy = fetch_policy(...)
        update_the_db(...)
        registry.push(policy, events.UPDATED)

    def delete_qos_policy(...):
        policy = fetch_policy(...)
        update_the_db(...)
        registry.push(policy, events.DELETED)


References
----------

.. [#ov_serdes] https://github.com/openstack/oslo.versionedobjects/blob/master/oslo_versionedobjects/tests/test_objects.py#L621
.. [#vo_mkcompat] https://github.com/openstack/oslo.versionedobjects/blob/master/oslo_versionedobjects/base.py#L460
.. [#vo_mkcptests] https://github.com/openstack/oslo.versionedobjects/blob/master/oslo_versionedobjects/tests/test_objects.py#L111
.. [#vo_versioning] https://github.com/openstack/oslo.versionedobjects/blob/master/oslo_versionedobjects/base.py#L236
