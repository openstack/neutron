
Neutron Metering system
~~~~~~~~~~~~~~~~~~~~~~~

The Neutron metering service enables operators to account the traffic in/out
of the OpenStack environment. The concept is quite simple, operators can
create metering labels, and decide if the labels are applied to all projects
(tenants) or if they are applied to a specific one. Then, the operator needs
to create traffic rules in the metering labels. The traffic rules are used
to match traffic in/out of the OpenStack environment, and the accounting of
packets and bytes is sent to the notification queue for further processing
by Ceilometer (or some other system that is consuming that queue). The
message sent in the queue is of type ``event``. Therefore, it requires an
event processing configuration to be added/enabled in Ceilometer.


The metering agent has the following configurations:

*  ``driver``: the driver used to implement the metering rules. The default
   is ``neutron.services.metering.drivers.noop``, which means, we do not
   execute anything in the networking host. The only driver implemented so far
   is ``neutron.services.metering.drivers.iptables.iptables_driver.IptablesMeteringDriver``.
   Therefore, only ``iptables`` is supported so far;

*  ``measure_interval``: the interval in seconds used to gather the bytes and
   packets information from the network plane. The default value is ``30``
   seconds;

*  ``report_interval``: the interval in secodns used to generated the report
   (message) of the data that is gathered. The default value is ``300``
   seconds.

*  ``granular_traffic_data``: Defines if the metering agent driver should
   present traffic data in a granular fashion, instead of grouping all of the
   traffic data for all projects and routers where the labels were assigned
   to. The default value is ``False`` for backward compatibility.

Non-granular traffic messages
-----------------------------
The non-granular (``granular_traffic_data = False``) traffic messages (here
also called as legacy) have the following format; bear in mind that if labels
are shared, then the counters are for all routers of all projects where the
labels were applied.

  .. code-block:: json

     {
      "pkts": "<the number of packets that matched the rules of the labels>",
      "bytes": "<the number of bytes that matched the rules of the labels>",
      "time": "<seconds between the first data collection and the last one>",
      "first_update": "timeutils.utcnow_ts() of the first collection",
      "last_update": "timeutils.utcnow_ts() of the last collection",
      "host": "<neutron metering agent host name>",
      "label_id": "<the label id>",
      "tenant_id": "<the tenant id>"
      }

The ``first_update`` and ``last_update`` timestamps represent the moment
when the first and last data collection happened within the report interval.
On the other hand, the ``time`` represents the difference between those two
timestamp.

The ``tenant_id`` is only consistent when labels are not shared. Otherwise,
they will contain the project id of the last router of the last project
processed when the agent is started up. In other words, it is better not
use it when dealing with shared labels.

All of the messages generated in this configuration mode are sent to the
message bus as ``l3.meter`` events.

Granular traffic messages
-------------------------
The granular (``granular_traffic_data = True``) traffic messages allow
operators to obtain granular information for shared metering labels.
Therefore, a single label, when configured as ``shared=True`` and applied in
all projects/routers of the environment, it will generate data in a granular
fashion.

It (the metering agent) will account the traffic counter data in the
following granularities.

* ``label`` -- all of the traffic counter for a given label. One must bear
  in mind that a label can be assigned to multiple routers. Therefore, this
  granularity represents all aggregation for all data for all routers of all
  projects where the label has been applied.

* ``router`` -- all of the traffic counter for all labels that are assigned to
  the router.

* ``project`` -- all of the traffic counters for all labels of all routers that
  a project has.

* ``router-label`` -- all of the traffic counters for a router and the given
  label.

* ``project-label`` -- all of the traffic counters for all routers of a project
  that have a given label.

Each granularity presented here is sent to the message bus with different
events types that vary according to the granularity. The mapping between
granularity and event type is presented as follows.

* ``label`` -- event type ``l3.meter.label``.

* ``router`` -- event type ``l3.meter.router``.

* ``project`` -- event type ``l3.meter.project``..

* ``router-label`` -- event type ``l3.meter.label_router``.

* ``project-label`` -- event type ``l3.meter.label_project``.

Furthermore, we have metadata that is appended to the messages depending on
the granularity. As follows we present the mapping between the granularities
and the metadata that will be available.

* ``label``, ``router-label``, and ``project-label`` granularities -- have the
  metadata ``label_id``, ``label_name``, ``label_shared``, ``project_id`` (if
  shared, this value will come with ``all`` for the ``label`` granularity), and
  ``router_id`` (only for ``router-label`` granularity).

* The ``router`` granularity -- has the ``router_id`` and ``project_id``
  metadata.

* The ``project`` granularity only has the ``project_id`` metadata.

The message will also contain some attributes that can be found in the
legacy mode such as ``bytes``, ``pkts``, ``time``, ``first_update``,
``last_update``, and ``host``. As follows we present an example of JSON message
with all of the possible attributes.

  .. code-block:: json

     {
     "resource_id": "router-f0f745d9a59c47fdbbdd187d718f9e41-label-00c714f1-49c8-462c-8f5d-f05f21e035c7",
      "project_id": "f0f745d9a59c47fdbbdd187d718f9e41",
      "first_update": 1591058790,
      "bytes": 0,
      "label_id": "00c714f1-49c8-462c-8f5d-f05f21e035c7",
      "label_name": "test1",
      "last_update": 1591059037,
      "host": "<hostname>",
      "time": 247,
      "pkts": 0,
      "label_shared": true
      }

The ``resource_id`` is a unique identified for the "resource" being
monitored. Here we consider a resource to be any of the granularities that
we handle.

Sample of metering_agent.ini
----------------------------

As follows we present all of the possible configuration one can use in the
metering agent init file.

.. show-options::
   :config-file: etc/oslo-config-generator/metering_agent.ini