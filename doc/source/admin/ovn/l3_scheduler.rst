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
scheduling, no ``Gateway_Chassis`` will be assigned and no value will be set
in the "options" column of the ``Logical_Router`` register; that will be used
to detect an unhosted router gateway port.


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


Availability Zones (AZ) distribution
------------------------------------

Both the ``OVNGatewayChanceScheduler`` and the
``OVNGatewayLeastLoadedScheduler`` schedulers have the Availability Zones (AZ)
in consideration. If a router has any AZ defined, the schedulers will select
only those chassis located in the AZs. If no chassis meets this condition, the
``Logical_Router_Port`` won't be assigned to any chassis and won't be bound.

Once the list of candidate ``Chassis`` (depending on the scheduler selected)
is created, this list is reordered to prioritize these ``Chassis`` from
different AZs. That will spread the allocation choices to all AZs; if the
current (and highest) ``Chassis`` binding fails, the next ``Chassis`` in the
list will belong to another AZ.

This improvement was implemented in [3]_.


Soft Anti-Affinity for ``Logical_Router`` with multiple ``Logical_Router_Port``
-------------------------------------------------------------------------------

Support for multiple gateway ports [4]_ was implemented to support
configurations that provide resiliency and load sharing across multiple router
ports at the layer 3 level.

In addition to external dependencies such as BFD for liveness detection and
ECMP for load sharing accross default routes, the feature required changes to
the scheduler, the goal being that each ``Logical_Router_Port`` record for a
``Logical_Router`` would have a different set of ``Chassis`` for each priority.

The Anti-Affinity is accomplished by having the OVN driver provide the router
object subject to scheduling to the scheduler. The scheduler then checks
whether there already exists ``Logical_Router_Port`` records for the target
router, and makes any ``Chassis`` involed in the already existing ports
appear as having higher load, making it less likely that the already used
``Chassis`` gets picked for a new ``Logical_Router_Port``.

Since the algorithm is based on load and priority, Anti-Affinity is only
supported for the ``OVNGatewayLeastLoadedScheduler``.


This improvement was implemented in [5]_.


References
----------

.. [1] https://review.opendev.org/c/openstack/neutron/+/893653
.. [2] https://review.opendev.org/c/openstack/neutron/+/893654
.. [3] https://review.opendev.org/c/openstack/neutron/+/892604
.. [4] https://review.opendev.org/c/openstack/neutron-specs/+/870030
.. [5] https://review.opendev.org/c/openstack/neutron/+/873699
