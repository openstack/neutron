.. _notification-events:

======================
Notification events
======================

Neutron emits legacy (unversioned) notifications. Payload fields follow the
Neutron API resource schema for the corresponding operation. There is no
formal backward compatibility guarantee for notification payloads.

Resource CRUD events
====================

For every REST API resource exposed by Neutron and its extensions, create,
update, and delete operations emit notifications with the following event
type patterns:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Event type
     - When emitted
   * - ``<resource>.create.start``
     - Before the create operation runs
   * - ``<resource>.create.end``
     - After a successful create (HTTP 2xx)
   * - ``<resource>.update.start``
     - Before the update operation runs
   * - ``<resource>.update.end``
     - After a successful update (HTTP 2xx)
   * - ``<resource>.delete.start``
     - Before the delete operation runs
   * - ``<resource>.delete.end``
     - After a successful delete (HTTP 2xx/204)

``<resource>`` is the singular resource name used internally by the API
(for example, ``network``, ``subnet``, ``port``, ``router``,
``security_group``). Extension resources follow the same pattern using their
registered resource name.

Payload format
--------------

Create
^^^^^^

* ``<resource>.create.start`` — the request body sent to the API.

  Example for ``network.create.start``::

      {
          "network": {
              "name": "private-net",
              "admin_state_up": true
          }
      }

* ``<resource>.create.end`` — the API response body containing the created
  resource.

  Example for ``network.create.end``::

      {
          "network": {
              "id": "9eaa96ed-c2d2-45a7-a6d5-5f276a3a1b54",
              "name": "private-net",
              "admin_state_up": true,
              "status": "ACTIVE",
              "project_id": "0e33d3b1881045c3ac1b1cb9df3e0477",
          }
      }

Bulk create operations send a single ``*.start`` notification with the bulk
request body and a single ``*.end`` notification with the bulk response body.

Update
^^^^^^

* ``<resource>.update.start`` — the request body with an additional ``id``
  field set to the resource identifier.

  Example for ``network.update.start``::

      {
          "network": {
              "name": "renamed-net"
          },
          "id": "9eaa96ed-c2d2-45a7-a6d5-5f276a3a1b54"
      }

* ``<resource>.update.end`` — the API response body containing the updated
  resource.

Delete
^^^^^^

* ``<resource>.delete.start`` — a dictionary containing the resource ID::

      {
          "network_id": "9eaa96ed-c2d2-45a7-a6d5-5f276a3a1b54"
      }

* ``<resource>.delete.end`` — the deleted resource dictionary plus the
  resource ID field::

      {
          "network_id": "9eaa96ed-c2d2-45a7-a6d5-5f276a3a1b54",
          "network": {
              "id": "9eaa96ed-c2d2-45a7-a6d5-5f276a3a1b54",
              "name": "private-net",
              "admin_state_up": true,
              "status": "ACTIVE",
              "project_id": "0e33d3b1881045c3ac1b1cb9df3e0477"
          }
      }

Core resources
--------------

The following core resources emit CRUD notifications when created, updated, or
deleted through the API:

* ``network``
* ``subnet``
* ``subnetpool``
* ``port``

L3 and security resources (when the corresponding extensions are loaded)
include ``router``, ``floatingip``, ``security_group``, and
``security_group_rule``.

Any other API extension that exposes standard CRUD endpoints also emits
notifications following the same pattern. Refer to the
`Network API reference <https://docs.openstack.org/api-ref/network/>`_ for the
full list of resources and their attributes.

Example: port update
^^^^^^^^^^^^^^^^^^^^

Full notification for ``port.update.end``::

    {
        "priority": "INFO",
        "event_type": "port.update.end",
        "timestamp": "2026-05-28T12:00:00.000000",
        "publisher_id": "network.myhost",
        "message_id": "f6b2e828-4a28-47b7-8f9d-96a3185bcdb0",
        "payload": {
            "port": {
                "id": "42a5e466-2c4e-4c58-b357-8b2459891066",
                "name": "server-port",
                "network_id": "9eaa96ed-c2d2-45a7-a6d5-5f276a3a1b54",
                "mac_address": "fa:16:3e:42:61:26",
                "admin_state_up": true,
                "status": "ACTIVE",
                "device_id": "instance-uuid",
                "device_owner": "compute:nova",
                "fixed_ips": [
                    {
                        "subnet_id": "b9304367-404e-4c1a-9bc3-abac6cc92d1d",
                        "ip_address": "192.168.1.10"
                    }
                ],
                "project_id": "0e33d3b1881045c3ac1b1cb9df3e0477"
            }
        }
    }

Special events
==============

In addition to the generic CRUD notifications, Neutron emits the following
special-purpose events.

Router interface
----------------

Emitted when a subnet is added to or removed from a router.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Event type
     - When emitted
   * - ``router.interface.create``
     - After a subnet is added to a router
   * - ``router.interface.delete``
     - After a subnet is removed from a router

Payload::

    {
        "router_interface": {
            "id": "<router_id>",
            "project_id": "<project_id>",
            "port_id": "<port_id>",
            "network_id": "<network_id>",
            "subnet_id": "<subnet_id>",
            "subnet_ids": ["<subnet_id>"]
        }
    }

Resource tags
-------------

Emitted when tags are created, updated, or deleted on a taggable resource.
Tag operations emit both ``*.start`` and ``*.end`` pairs.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Event type
     - When emitted
   * - ``tag.create.start`` / ``tag.create.end``
     - Before and after tags are created on a resource
   * - ``tag.update.start`` / ``tag.update.end``
     - Before and after tags are updated on a resource
   * - ``tag.delete.start`` / ``tag.delete.end``
     - Before and after tags are deleted from a resource
   * - ``tag.delete_all.start`` / ``tag.delete_all.end``
     - Before and after all tags are deleted from a resource

Payload::

    {
        "obj_resource": "<resource_type>",
        "obj_resource_id": "<resource_id>",
        "tags": ["tag1", "tag2"]
    }

The ``tags`` field is present when tags are being set. Taggable resources
include networks, subnets, subnetpools, ports, routers, floating IPs,
security groups, security group rules, trunks, and other resources that
support standard attributes.

Agent scheduling
----------------

Emitted when a network or router is assigned to or removed from an agent.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Event type
     - When emitted
   * - ``dhcp_agent.network.add``
     - Network scheduled to a DHCP agent
   * - ``dhcp_agent.network.remove``
     - Network removed from a DHCP agent
   * - ``l3_agent.router.add``
     - Router scheduled to an L3 agent
   * - ``l3_agent.router.remove``
     - Router removed from an L3 agent

Payload for DHCP agent events::

    {
        "agent": {
            "id": "<agent_id>",
            "network_id": "<network_id>"
        }
    }

Payload for L3 agent events::

    {
        "agent": {
            "id": "<agent_id>",
            "router_id": "<router_id>"
        }
    }

Metering
--------

The metering agent periodically reports traffic counters.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Event type
     - When emitted
   * - ``l3.meter``
     - Default traffic report
   * - ``l3.meter.<granularity>``
     - Granular traffic report

Payload::

    {
        "pkts": 1000,
        "bytes": 1500000,
        "time": 300,
        "first_update": "2026-05-28T11:55:00.000000",
        "last_update": "2026-05-28T12:00:00.000000",
        "host": "network-node-1",
        "label_id": "<metering_label_id>",
        "project_id": "<project_id>"
    }

When granular traffic data is enabled, the payload may also include
``resource_id``, ``label_name``, and ``label_shared`` fields instead of or in
addition to ``label_id``.

Usage audit
-----------

The ``neutron-usage-audit`` cron script emits existence notifications for all
resources currently in the database. These are used by billing and monitoring
systems.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Event type
     - Payload key
   * - ``network.exists``
     - ``network``
   * - ``subnet.exists``
     - ``subnet``
   * - ``port.exists``
     - ``port``
   * - ``router.exists``
     - ``router``
   * - ``floatingip.exists``
     - ``floatingip``

Each payload contains the full resource dictionary under the corresponding
key, for example ``{"network": {<network_dict>}}``.
