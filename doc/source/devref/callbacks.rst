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


Neutron Callback System
=======================

In Neutron, core and service components may need to cooperate during the
execution of certain operations, or they may need to react upon the occurrence
of certain events. For instance, when a Neutron resource is associated to
multiple services, the components in charge of these services may need to play
an active role in determining what the right state of the resource needs to be.

The cooperation may be achieved by making each object aware of each other, but
this leads to tight coupling, or alternatively it can be achieved by using a
callback-based system, where the same objects are allowed to cooperate in a
loose manner.

This is particularly important since the spin off of the advanced services like
VPN, Firewall and Load Balancer, where each service's codebase lives independently
from the core and from one another. This means that the tight coupling is no longer
a practical solution for object cooperation. In addition to this, if more services
are developed independently, there is no viable integration between them and the
Neutron core. A callback system, and its registry, tries to address these issues.

In object-oriented software systems, method invocation is also known as message
passing: an object passes a message to another object, and it may or may not expect
a message back. This point-to-point interaction can take place between the parties
directly involved in the communication, or it can happen via an intermediary. The
intermediary is then in charge of keeping track of who is interested in the messages
and in delivering the messages forth and back, when required. As mentioned earlier,
the use of an intermediary has the benefit of decoupling the parties involved
in the communications, as now they only need to know about the intermediary; the
other benefit is that the use of an intermediary opens up the possibility of
multiple party communication: more than one object can express interest in
receiving the same message, and the same message can be delivered to more than
one object. To this aim, the intermediary is the entity that exists throughout
the system lifecycle, as it needs to be able to track whose interest is associated
to what message.

In a design for a system that enables callback-based communication, the following
aspects need to be taken into account:

* how to become consumer of messages (i.e. how to be on the receiving end of the message);
* how to become producer of messages (i.e. how to be on the sending end of the message);
* how to consume/produce messages selectively;

Translate and narrow this down to Neutron needs, and this means the design of a callback
system where messages are about lifecycle events (e.g. before creation, before
deletion, etc.) of Neutron resources (e.g. networks, routers, ports, etc.), where the
various parties can express interest in knowing when these events for a specific
resources take place.

Rather than keeping the conversation abstract, let us delve into some examples, that would
help understand better some of the principles behind the provided mechanism.


Subscribing to events
---------------------

Imagine that you have entity A, B, and C that have some common business over router creation.
A wants to tell B and C that the router has been created and that they need to get on and
do whatever they are supposed to do. In a callback-less world this would work like so:

::

  # A is done creating the resource
  # A gets hold of the references of B and C
  # A calls B
  # A calls C
  B->my_random_method_for_knowing_about_router_created()
  C->my_random_very_difficult_to_remember_method_about_router_created()

If B and/or C change, things become sour. In a callback-based world, things become a lot
more uniform and straightforward:

::

  # B and C ask I to be notified when A is done creating the resource

  # ...
  # A is done creating the resource
  # A gets hold of the reference to the intermediary I
  # A calls I
  I->notify()

Since B and C will have expressed interest in knowing about A's business, 'I' will
deliver the messages to B and C. If B and C changes, A and 'I' do not need to change.

In practical terms this scenario would be translated in the code below:

::

  from neutron.callbacks import events
  from neutron.callbacks import resources
  from neutron.callbacks import registry


  def callback1(resource, event, trigger, **kwargs):
      print('Callback1 called by trigger: ', trigger)
      print('kwargs: ', kwargs)

  def callback2(resource, event, trigger, **kwargs):
      print('Callback2 called by trigger: ', trigger)
      print('kwargs: ', kwargs)


  # B and C express interest with I
  registry.subscribe(callback1, resources.ROUTER, events.BEFORE_CREATE)
  registry.subscribe(callback2, resources.ROUTER, events.BEFORE_CREATE)
  print('Subscribed')


  # A notifies
  def do_notify():
      kwargs = {'foo': 'bar'}
      registry.notify(resources.ROUTER, events.BEFORE_CREATE, do_notify, **kwargs)


  print('Notifying...')
  do_notify()


The output is:

::

  > Subscribed
  > Notifying...
  > Callback2 called by trigger:  <function do_notify at 0x7f2a5d663410>
  > kwargs:  {'foo': 'bar'}
  > Callback1 called by trigger:  <function do_notify at 0x7f2a5d663410>
  > kwargs:  {'foo': 'bar'}

Thanks to the intermediary existence throughout the life of the system, A, B, and C
are flexible to evolve their internals, dynamics, and lifecycles.


Subscribing and aborting events
-------------------------------

Interestingly in Neutron, certain events may need to be forbidden from happening due to the
nature of the resources involved. To this aim, the callback-based mechanism has been designed
to support a use case where, when callbacks subscribe to specific events, the action that
results from it, may lead to the propagation of a message back to the sender, so that it itself
can be alerted and stop the execution of the activity that led to the message dispatch in the
first place.

The typical example is where a resource, like a router, is used by one or more high-level
service(s), like a VPN or a Firewall, and actions like interface removal or router destruction
cannot not take place, because the resource is shared.

To address this scenario, special events are introduced, 'BEFORE_*' events, to which callbacks
can subscribe and have the opportunity to 'abort', by raising an exception when notified.

Since multiple callbacks may express an interest in the same event for a particular resource,
and since callbacks are executed independently from one another, this may lead to situations
where notifications that occurred before the exception must be aborted. To this aim, when an
exception occurs during the notification process, an abort_* event is propagated immediately
after. It is up to the callback developer to determine whether subscribing to an abort
notification is required in order to revert the actions performed during the initial execution
of the callback (when the BEFORE_* event was fired). Exceptions caused by callbacks registered
to abort events are ignored. The snippet below shows this in action:

::

  from neutron.callbacks import events
  from neutron.callbacks import exceptions
  from neutron.callbacks import resources
  from neutron.callbacks import registry


  def callback1(resource, event, trigger, **kwargs):
      raise Exception('I am failing!')

  def callback2(resource, event, trigger, **kwargs):
      print('Callback2 called by %s on event  %s' % (trigger, event))


  registry.subscribe(callback1, resources.ROUTER, events.BEFORE_CREATE)
  registry.subscribe(callback2, resources.ROUTER, events.BEFORE_CREATE)
  registry.subscribe(callback2, resources.ROUTER, events.ABORT_CREATE)
  print('Subscribed')


  def do_notify():
      kwargs = {'foo': 'bar'}
      registry.notify(resources.ROUTER, events.BEFORE_CREATE, do_notify, **kwargs)


  print('Notifying...')
  try:
      do_notify()
  except exceptions.CallbackFailure as e:
      print('Error: ', e)

The output is:

::

  > Subscribed
  > Notifying...
  > Callback2 called by <function do_notify at 0x7f3194c7f410> on event  before_create
  > Callback2 called by <function do_notify at 0x7f3194c7f410> on event  abort_create
  > Error:  Callback __main__.callback1 failed with "I am failing!"

In this case, upon the notification of the BEFORE_CREATE event, Callback1 triggers an exception
that can be used to stop the action from taking place in do_notify(). On the other end, Callback2
will be executing twice, once for dealing with the BEFORE_CREATE event, and once to undo the
actions during the ABORT_CREATE event. It is worth noting that it is not mandatory to have
the same callback register to both BEFORE_* and the respective ABORT_* event; as a matter of
fact, it is best to make use of different callbacks to keep the two logic separate.

As we can see from the last example, exception which is triggered in some callback will be
recorded, and it will not prevent the other remaining callbacks execution. Exception triggered in
callback of BEFORE_XXX will make notify process generate an ABORT_XXX event and call the related
callback, while exception from PRECOMMIT_XXX will not generate ABORT_XXX event. But both of them
will finally raise a unified CallbackFailure exception to the outside. For the exception triggered
from other events, like AFTER_XXX and ABORT_XXX there will no exception raised to the outside.


Unsubscribing to events
-----------------------

There are a few options to unsubscribe registered callbacks:

* clear(): it unsubscribes all subscribed callbacks: this can be useful especially when
  winding down the system, and notifications shall no longer be triggered.
* unsubscribe(): it selectively unsubscribes a callback for a specific resource's event.
  Say callback C has subscribed to event A for resource R, any notification of event A
  for resource R will no longer be handed over to C, after the unsubscribe() invocation.
* unsubscribe_by_resource(): say that callback C has subscribed to event A, B, and C for
  resource R, any notification of events related to resource R will no longer be handed
  over to C, after the unsubscribe_by_resource() invocation.
* unsubscribe_all(): say that callback C has subscribed to events A, B for resource R1,
  and events C, D for resource R2, any notification of events pertaining resources R1 and
  R2 will no longer be handed over to C, after the unsubscribe_all() invocation.

The snippet below shows these concepts in action:

::

  from neutron.callbacks import events
  from neutron.callbacks import exceptions
  from neutron.callbacks import resources
  from neutron.callbacks import registry


  def callback1(resource, event, trigger, **kwargs):
      print('Callback1 called by %s on event %s for resource %s' % (trigger, event, resource))


  def callback2(resource, event, trigger, **kwargs):
      print('Callback2 called by %s on event %s for resource %s' % (trigger, event, resource))


  registry.subscribe(callback1, resources.ROUTER, events.BEFORE_READ)
  registry.subscribe(callback1, resources.ROUTER, events.BEFORE_CREATE)
  registry.subscribe(callback1, resources.ROUTER, events.AFTER_DELETE)
  registry.subscribe(callback1, resources.PORT, events.BEFORE_UPDATE)
  registry.subscribe(callback2, resources.ROUTER_GATEWAY, events.BEFORE_UPDATE)
  print('Subscribed')


  def do_notify():
      print('Notifying...')
      kwargs = {'foo': 'bar'}
      registry.notify(resources.ROUTER, events.BEFORE_READ, do_notify, **kwargs)
      registry.notify(resources.ROUTER, events.BEFORE_CREATE, do_notify, **kwargs)
      registry.notify(resources.ROUTER, events.AFTER_DELETE, do_notify, **kwargs)
      registry.notify(resources.PORT, events.BEFORE_UPDATE, do_notify, **kwargs)
      registry.notify(resources.ROUTER_GATEWAY, events.BEFORE_UPDATE, do_notify, **kwargs)


  do_notify()
  registry.unsubscribe(callback1, resources.ROUTER, events.BEFORE_READ)
  do_notify()
  registry.unsubscribe_by_resource(callback1, resources.PORT)
  do_notify()
  registry.unsubscribe_all(callback1)
  do_notify()
  registry.clear()
  do_notify()

The output is:

::

  Subscribed
  Notifying...
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event before_read for resource router
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event before_create for resource router
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event after_delete for resource router
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event before_update for resource port
  Callback2 called by <function do_notify at 0x7f062c8f67d0> on event before_update for resource router_gateway
  Notifying...
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event before_create for resource router
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event after_delete for resource router
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event before_update for resource port
  Callback2 called by <function do_notify at 0x7f062c8f67d0> on event before_update for resource router_gateway
  Notifying...
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event before_create for resource router
  Callback1 called by <function do_notify at 0x7f062c8f67d0> on event after_delete for resource router
  Callback2 called by <function do_notify at 0x7f062c8f67d0> on event before_update for resource router_gateway
  Notifying...
  Callback2 called by <function do_notify at 0x7f062c8f67d0> on event before_update for resource router_gateway
  Notifying...


FAQ
---

Are callbacks a mechanism for remote or local communication (intra vs inter-process)?

   Callbacks as described in this document are a local communication mechanism that
   allows multiple entities in the same process space to communicate with one another.
   For Neutron specific remote (IPC) mechanisms, you can see read more in
   :doc:`RPC API <rpc_api>` or :doc:`Messaging callbacks <rpc_callbacks>`.

Can I use the callbacks registry to subscribe and notify non-core resources and events?

   Short answer is yes. The callbacks module defines literals for what are considered core Neutron
   resources and events. However, the ability to subscribe/notify is not limited to these as you
   can use your own defined resources and/or events. Just make sure you use string literals, as
   typos are common, and the registry does not provide any runtime validation. Therefore, make
   sure you test your code!

What is the relationship between Callbacks and Taskflow?

   There is no overlap between Callbacks and Taskflow or mutual exclusion; as matter of fact they
   can be combined; You could have a callback that goes on and trigger a taskflow. It is a nice
   way of separating implementation from abstraction, because you can keep the callback in place
   and change Taskflow with something else.

Is there any ordering guarantee during notifications?

  No, the ordering in which callbacks are notified is completely arbitrary by design: callbacks
  should know nothing about each other, and ordering should not matter; a callback will always be
  notified and its outcome should always be the same regardless as to in which order is it
  notified. Priorities can be a future extension, if a use case arises that require enforced
  ordering.

How is the the notifying object expected to interact with the subscribing objects?

  The ``notify`` method implements a one-way communication paradigm: the notifier sends a message
  without expecting a response back (in other words it fires and forget). However, due to the nature
  of Python, the payload can be mutated by the subscribing objects, and this can lead to unexpected
  behavior of your code, if you assume that this is the intentional design. Bear in mind, that
  passing-by-value using deepcopy was not chosen for efficiency reasons. Having said that, if you
  intend for the notifier object to expect a response, then the notifier itself would need to act
  as a subscriber.

Is the registry thread-safe?

  Short answer is no: it is not safe to make mutations while callbacks are being called (more
  details as to why can be found `here <https://hg.python.org/releasing/2.7.9/file/753a8f457ddc/Objects/dictobject.c#l937>`_).
  A mutation could happen if a 'subscribe'/'unsubscribe' operation interleaves with the execution
  of the notify loop. Albeit there is a possibility that things may end up in a bad state, the
  registry works correctly under the assumption that subscriptions happen at the very beginning
  of the life of the process and that the unsubscriptions (if any) take place at the very end.
  In this case, chances that things do go badly may be pretty slim. Making the registry
  thread-safe will be considered as a future improvement.

What kind of operation I can add into callback?

  For callback function of PRECOMMIT_XXX events, we can't use blocking functions or a function
  that would take a long time, like communicating to SDN controller over network.
  Callbacks for PRECOMMIT events are meant to execute DB operations in a transaction context. The
  errors that occur will be taken care by the context manager.

What kind of function can be a callback?

  Anything you fancy: lambdas, 'closures', class, object or module methods. For instance:

::

  from neutron.callbacks import events
  from neutron.callbacks import resources
  from neutron.callbacks import registry


  def callback1(resource, event, trigger, **kwargs):
      print('module callback')


  class MyCallback(object):

      def callback2(self, resource, event, trigger, **kwargs):
          print('object callback')

      @classmethod
      def callback3(cls, resource, event, trigger, **kwargs):
          print('class callback')


  c = MyCallback()
  registry.subscribe(callback1, resources.ROUTER, events.BEFORE_CREATE)
  registry.subscribe(c.callback2, resources.ROUTER, events.BEFORE_CREATE)
  registry.subscribe(MyCallback.callback3, resources.ROUTER, events.BEFORE_CREATE)

  def do_notify():
      def nested_subscribe(resource, event, trigger, **kwargs):
          print('nested callback')

      registry.subscribe(nested_subscribe, resources.ROUTER, events.BEFORE_CREATE)

      kwargs = {'foo': 'bar'}
      registry.notify(resources.ROUTER, events.BEFORE_CREATE, do_notify, **kwargs)


  print('Notifying...')
  do_notify()

And the output is going to be:

::

  Notifying...
  module callback
  object callback
  class callback
  nested callback
