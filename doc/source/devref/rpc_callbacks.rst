=================================
Neutron Messaging Callback System
=================================

Neutron already has a callback system [link-to: callbacks.rst] for
in-process resource callbacks where publishers and subscribers are able
to publish, subscribe and extend resources.

This system is different, and is intended to be used for inter-process
callbacks, via the messaging fanout mechanisms.

In Neutron, agents may need to subscribe to specific resource details which
may change over time. And the purpose of this messaging callback system
is to allow agent subscription to those resources without the need to extend
modify existing RPC calls, or creating new RPC messages.

A few resource which can benefit of this system:

* security groups members
* security group rules,
* QoS policies.

Using a remote publisher/subscriber pattern, the information about such
resources could be published using fanout queues to all interested nodes,
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
allow object version down/up conversion. #[vo_mkcompat]_ #[vo_mkcptests]_

For the VO's versioning schema look here: #[vo_versioning]_



versioned_objects serialization/deserialization with the
obj_to_primitive(target_version=..) and primitive_to_obj() #[ov_serdes]_
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

a) During upgrades, we pin neutron-server to a compatible version for resource
   fanout updates, and server sends both the old, and the newer version to
   different topic, queues. Old agents receive the updates on the old version
   topic, new agents receive updates on the new version topic.
   When the whole system upgraded, we un-pin the compatible version fanout.

   A variant of this could be using a single fanout queue, and sending the
   pinned version of the object to all. Newer agents can deserialize to the
   latest version and upgrade any fields internally. Again at the end, we
   unpin the version and restart the service.

b) The subscriber will rpc call the publisher to start publishing also a downgraded
   version of the object on every update on a separate queue. The complication
   of this version, is the need to ignore new version objects as long as we keep
   receiving the downgraded ones, and otherwise resend the request to send the
   downgraded objects after a certain timeout (thinking of the case where the
   request for downgraded queue is done, but the publisher restarted).
   This approach is more complicated to implement, but more automated from the
   administrator point of view. We may want to look into it as a second step
   from a

c) The subscriber will send a registry.get_info for the latest specific version
   he knows off. This can have scalability issues during upgrade as any outdated
   agent will require a flow of two messages (request, and response). This is
   indeed very bad at scale if you have hundreds or thousands of agents.

Option a seems like a reasonable strategy, similar to what nova does now with
versioned objects.

Serialized versioned objects look like::

   {'versioned_object.version': '1.0',
    'versioned_object.name': 'QoSProfile',
    'versioned_object.data': {'rules': [
                                        {'versioned_object.version': '1.0',
                                         'versioned_object.name': 'QoSRule',
                                         'versioned_object.data': {'name': u'a'},
                                         'versioned_object.namespace': 'versionedobjects'}
                                        ],
                              'uuid': u'abcde',
                              'name': u'aaa'},
    'versioned_object.namespace': 'versionedobjects'}

Topic names for the fanout queues
=================================

if we adopted option a:
neutron-<resouce_type>_<resource_id>-<vo_version>
[neutron-<resouce_type>_<resource_id>-<vo_version_compat>]

if we adopted option b for rolling upgrades:
neutron-<resource_type>-<resource_id>
neutron-<resource_type>-<resource_id>-<vo_version>

for option c, just:
neutron-<resource_type>-<resource_id>

Subscribing to resources
========================

Imagine that you have agent A, which just got to handle a new port, which
has an associated security group, and QoS policy.

The agent code processing port updates may look like::

    from neutron.rpc_resources import events
    from neutron.rpc_resources import resources
    from neutron.rpc_resources import registry


    def process_resource_updates(resource_type, resource_id, resource_list, action_type):

        # send to the right handler which will update any control plane
        # details related to the updated resource...


    def port_update(...):

        # here we extract sg_id and qos_policy_id from port..

        registry.subscribe(resources.SG_RULES, sg_id,
                           callback=process_resource_updates)
        sg_rules = registry.get_info(resources.SG_RULES, sg_id)

        registry.subscribe(resources.SG_MEMBERS, sg_id,
                           callback=process_resource_updates)
        sg_members = registry.get_info(resources.SG_MEMBERS, sg_id)

        registry.subscribe(resources.QOS_RULES, qos_policy_id,
                           callback=process_resource_updates)
        qos_rules = registry.get_info(resources.QOS_RULES, qos_policy_id,
                                      callback=process_resource_updates)

        cleanup_subscriptions()


    def cleanup_subscriptions()
        sg_ids = determine_unreferenced_sg_ids()
        qos_policy_id = determine_unreferenced_qos_policy_ids()
        registry.unsubscribe_info(resource.SG_RULES, sg_ids)
        registry.unsubscribe_info(resource.SG_MEMBERS, sg_ids)
        registry.unsubscribe_info(resource.QOS_RULES, qos_policy_id)

Another unsubscription strategy could be to lazily unsubscribe resources when
we receive updates for them, and we discover that they are not needed anymore.

Deleted resources are automatically unsubscribed as we receive the delete event.

NOTE(irenab): this could be extended to core resources like ports, making use
of the standard neutron in-process callbacks at server side and propagating
AFTER_UPDATE events, for example, but we may need to wait until those callbacks
are used with proper versioned objects.


Unsubscribing to resources
==========================

There are a few options to unsubscribe registered callbacks:

* unsubscribe_resource_id(): it selectively unsubscribes an specific
                             resource type + id.
* unsubscribe_resource_type(): it unsubscribes from an specific resource type,
                               any ID.
* unsubscribe_all(): it unsubscribes all subscribed resources and ids.


Sending resource updates
========================

On the server side, resource updates could come from anywhere, a service plugin,
an extension, anything that updates the resource and that it's of any interest
to the agents.

The server/publisher side may look like::

    from neutron.rpc_resources import events
    from neutron.rpc_resources import resources
    from neutron.rpc_resources import registry as rpc_registry

    def add_qos_x_rule(...):
        update_the_db(...)
        send_rpc_updates_on_qos_policy(qos_policy_id)

    def del_qos_x_rule(...):
        update_the_db(...)
        send_rpc_deletion_of_qos_policy(qos_policy_id)

    def send_rpc_updates_on_qos_policy(qos_policy_id):
        rules = get_qos_policy_rules_versioned_object(qos_policy_id)
        rpc_registry.notify(resources.QOS_RULES, qos_policy_id, rules, events.UPDATE)

    def send_rpc_deletion_of_qos_policy(qos_policy_id):
        rpc_registry.notify(resources.QOS_RULES, qos_policy_id, None, events.DELETE)

    # This part is added for the registry mechanism, to be able to request
    # older versions of the notified objects if any oudated agent requires
    # them.
    def retrieve_older_version_callback(qos_policy_id, version):
        return get_qos_policy_rules_versioned_object(qos_policy_id, version)

    rpc_registry.register_retrieve_callback(resource.QOS_RULES,
                                            retrieve_older_version_callback)

References
==========
.. [#ov_serdes] https://github.com/openstack/oslo.versionedobjects/blob/master/oslo_versionedobjects/tests/test_objects.py#L621
.. [#vo_mkcompat] https://github.com/openstack/oslo.versionedobjects/blob/master/oslo_versionedobjects/base.py#L460
.. [#vo_mkcptests] https://github.com/openstack/oslo.versionedobjects/blob/master/oslo_versionedobjects/tests/test_objects.py#L111
.. [#vo_versioning] https://github.com/openstack/oslo.versionedobjects/blob/master/oslo_versionedobjects/base.py#L236
