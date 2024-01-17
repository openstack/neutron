.. _l3_scheduler:

================
OVN L3 scheduler
================

Introduction
------------

The OVN L3 scheduler assigns the router gateway ports to a list of chassis.
Having more than one chassis assigned allows the service to have high
availability: if the ``Logical_Router_Port`` acting as gateway is assigned
to a failed chassis, OVN will bind this port to the next chassis in the list.
This list of chassis is prioritized; the ``Logical_Router_Port`` will be bound
to the chassis in the defined order.

This is done by associating multiple ``Gateway_Chassis`` rows with a
``Logical_Router_Port`` in the OVN Northbound database. A ``Gateway_Chassis``
register is just a link to a ``Chassis`` register and a priority. For the
same ``Logical_Router_Port``, all ``Gateway_Chassis`` assigned will have
a different priority, starting from 1 (the lowest priority) up to the number of
``Gateway_Chassis`` assigned.

The maximum number of ``Gateway_Chassis`` that can be assigned to a
``Logical_Router_Port`` is 5. This number is hardcoded. That means in Neutron
the highest priority a ``Gateway_Chassis`` will have is 5.

If no gateway chassis are available during the ``Logical_Router_Port``
scheduling, no ``Gateway_Chassis`` will be assigned and the value
"neutron-ovn-invalid-chassis" will be set in the "options" column of the
``Logical_Router`` register; that value will be used to detect an unhosted
router gateway port.


Types of schedulers
-------------------

The OVN L3 scheduler is configurable and allows us to implement several types
of algorithms. There are currently two implemented in the in-tree repository:

* ``OVNGatewayChanceScheduler``
* ``OVNGatewayLeastLoadedScheduler``


``OVNGatewayChanceScheduler``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The scheduler algorithm in this class is very simple: from the list of gateway
chassis provided (candidate chassis), it shuffles and returns the list.


``OVNGatewayLeastLoadedScheduler``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The goal of this scheduler is to balance the available chassis to host the same
number of ``Logical_Router_Port``. Since [1]_, the scheduler will retrieve the
list of available candidates and will assign, per priority, the least loaded
chassis. That means this scheduler will not only consider the chassis with
bound ``Logical_Router_Port`` (highest priority gateway chassis), but it will
balance also the lower priority assignations. This is done by (1) iterating
over the list of priorities (from 1 to the number of chassis to schedule), (2)
creating a list of ``Logical_Router_Port`` assigned to each ``Chassis`` **on
the select priority** and (3) selecting the least loaded ``Chassis``


Re-schedule ``Logical_Router_Port`` if a ``Chassis`` is removed
---------------------------------------------------------------

When a gateway ``Chassis`` is removed from the environment, it creates a "hole"
in the ``Gateway_Chassis`` assignation for a ``Logical_Router_Port``. The
``Gateway_Chassis`` register associated to the removed ``Chassis`` is deleted
and removed from the list of HA assigned ``Chassis``. This event is captured
by Neutron, which re-schedules ``Gateway_Chassis`` to create a balanced list
of assignations, same as done in ``OVNGatewayLeastLoadedScheduler``. This was
implemented in [2]_.

This process only applies to the lower priority ``Gateway_Chassis`` registers,
never the upper one; this is because the ``Logical_Router_Port`` is bound to
this ``Chassis`` and could be transmitting. If the highest ``Gateway_Chassis``
is changed, the ``Logical_Router_Port`` is bound to the new ``Chassis`` and
could break any active sessions.


References
----------

.. [1] https://review.opendev.org/c/openstack/neutron/+/893653
.. [2] https://review.opendev.org/c/openstack/neutron/+/893654
