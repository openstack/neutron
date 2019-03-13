.. _config-az:

==================
Availability zones
==================

An availability zone groups network nodes that run services like DHCP, L3, FW,
and others. It is defined as an agent's attribute on the network node. This
allows users to associate an availability zone with their resources so that the
resources get high availability.


Use case
--------

An availability zone is used to make network resources highly available. The
operators group the nodes that are attached to different power sources under
separate availability zones and configure scheduling for resources with high
availability so that they are scheduled on different availability zones.


Required extensions
-------------------

The core plug-in must support the ``availability_zone`` extension. The core
plug-in also must support the ``network_availability_zone`` extension to
schedule a network according to availability zones. The ``Ml2Plugin`` supports
it. The router service plug-in must support the ``router_availability_zone``
extension to schedule a router according to the availability zones. The
``L3RouterPlugin`` supports it.

.. code-block:: console

    $ openstack extension list --network -c Alias -c Name
    +---------------------------+---------------------------+
    | Name                      | Alias                     |
    +---------------------------+---------------------------+
    ...
    | Network Availability Zone | network_availability_zone |
    ...
    | Availability Zone         | availability_zone         |
    ...
    | Router Availability Zone  | router_availability_zone  |
    ...
    +---------------------------+---------------------------+


Availability zone of agents
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``availability_zone`` attribute can be defined in ``dhcp-agent`` and
``l3-agent``. To define an availability zone for each agent, set the
value into ``[AGENT]`` section of ``/etc/neutron/dhcp_agent.ini`` or
``/etc/neutron/l3_agent.ini``:

.. code-block:: ini

    [AGENT]
    availability_zone = zone-1

To confirm the agent's availability zone:

.. code-block:: console

    $ openstack network agent show 116cc128-4398-49af-a4ed-3e95494cd5fc
    +---------------------+---------------------------------------------------+
    | Field               | Value                                             |
    +---------------------+---------------------------------------------------+
    | admin_state_up      | UP                                                |
    | agent_type          | DHCP agent                                        |
    | alive               | True                                              |
    | availability_zone   | zone-1                                            |
    | binary              | neutron-dhcp-agent                                |
    | configurations      | dhcp_driver='neutron.agent.linux.dhcp.Dnsmasq',   |
    |                     | dhcp_lease_duration='86400',                      |
    |                     | log_agent_heartbeats='False', networks='2',       |
    |                     | notifies_port_ready='True', ports='6', subnets='4 |
    | created_at          | 2016-12-14 00:25:54                               |
    | description         | None                                              |
    | heartbeat_timestamp | 2016-12-14 06:20:24                               |
    | host                | ankur-desktop                                     |
    | id                  | 116cc128-4398-49af-a4ed-3e95494cd5fc              |
    | started_at          | 2016-12-14 00:25:54                               |
    | topic               | dhcp_agent                                        |
    +---------------------+---------------------------------------------------+

    $ openstack network agent show 9632309a-2aa4-4304-8603-c4de02c4a55f
    +---------------------+-------------------------------------------------+
    | Field               | Value                                           |
    +---------------------+-------------------------------------------------+
    | admin_state_up      | UP                                              |
    | agent_type          | L3 agent                                        |
    | alive               | True                                            |
    | availability_zone   | zone-1                                          |
    | binary              | neutron-l3-agent                                |
    | configurations      | agent_mode='legacy', ex_gw_ports='2',           |
    |                     | floating_ips='0',                               |
    |                     | gateway_external_network_id='',                 |
    |                     | handle_internal_only_routers='True',            |
    |                     | interface_driver='openvswitch', interfaces='4', |
    |                     | log_agent_heartbeats='False', routers='2'       |
    | created_at          | 2016-12-14 00:25:58                             |
    | description         | None                                            |
    | heartbeat_timestamp | 2016-12-14 06:20:28                             |
    | host                | ankur-desktop                                   |
    | id                  | 9632309a-2aa4-4304-8603-c4de02c4a55f            |
    | started_at          | 2016-12-14 00:25:58                             |
    | topic               | l3_agent                                        |
    +---------------------+-------------------------------------------------+


Availability zone related attributes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following attributes are added into network and router:

.. list-table::
   :header-rows: 1
   :widths: 25 10 10 10 50

   * - Attribute name
     - Access
     - Required
     - Input type
     - Description

   * - availability_zone_hints
     - RW(POST only)
     - No
     - list of string
     - availability zone candidates for the resource

   * - availability_zones
     - RO
     - N/A
     - list of string
     - availability zones for the resource

Use ``availability_zone_hints`` to specify the zone in which the resource is
hosted:

.. code-block:: console

    $ openstack network create --availability-zone-hint zone-1 \
    --availability-zone-hint zone-2 net1
    +---------------------------+--------------------------------------+
    | Field                     | Value                                |
    +---------------------------+--------------------------------------+
    | admin_state_up            | UP                                   |
    | availability_zone_hints   | zone-1                               |
    |                           | zone-2                               |
    | availability_zones        |                                      |
    | created_at                | 2016-12-14T06:23:36Z                 |
    | description               |                                      |
    | headers                   |                                      |
    | id                        | ad88e059-e7fa-4cf7-8857-6731a2a3a554 |
    | ipv4_address_scope        | None                                 |
    | ipv6_address_scope        | None                                 |
    | mtu                       | 1450                                 |
    | name                      | net1                                 |
    | port_security_enabled     | True                                 |
    | project_id                | cfd1889ac7d64ad891d4f20aef9f8d7c     |
    | provider:network_type     | vxlan                                |
    | provider:physical_network | None                                 |
    | provider:segmentation_id  | 77                                   |
    | revision_number           | 3                                    |
    | router:external           | Internal                             |
    | shared                    | False                                |
    | status                    | ACTIVE                               |
    | subnets                   |                                      |
    | tags                      | []                                   |
    | updated_at                | 2016-12-14T06:23:37Z                 |
    +---------------------------+--------------------------------------+



.. code-block:: console

    $ openstack router create --ha --availability-zone-hint zone-1 \
    --availability-zone-hint zone-2 router1
    +-------------------------+--------------------------------------+
    | Field                   | Value                                |
    +-------------------------+--------------------------------------+
    | admin_state_up          | UP                                   |
    | availability_zone_hints | zone-1                               |
    |                         | zone-2                               |
    | availability_zones      |                                      |
    | created_at              | 2016-12-14T06:25:40Z                 |
    | description             |                                      |
    | distributed             | False                                |
    | external_gateway_info   | null                                 |
    | flavor_id               | None                                 |
    | ha                      | False                                |
    | headers                 |                                      |
    | id                      | ced10262-6cfe-47c1-8847-cd64276a868c |
    | name                    | router1                              |
    | project_id              | cfd1889ac7d64ad891d4f20aef9f8d7c     |
    | revision_number         | 3                                    |
    | routes                  |                                      |
    | status                  | ACTIVE                               |
    | tags                    | []                                   |
    | updated_at              | 2016-12-14T06:25:40Z                 |
    +-------------------------+--------------------------------------+



Availability zone is selected from ``default_availability_zones`` in
``/etc/neutron/neutron.conf`` if a resource is created without
``availability_zone_hints``:

.. code-block:: ini

    default_availability_zones = zone-1,zone-2

To confirm the availability zone defined by the system:

.. code-block:: console

    $ openstack availability zone list
    +-----------+-------------+
    | Zone Name | Zone Status |
    +-----------+-------------+
    | zone-1    | available   |
    | zone-2    | available   |
    | zone-1    | available   |
    | zone-2    | available   |
    +-----------+-------------+

Look at the ``availability_zones`` attribute of each resource to confirm in
which zone the resource is hosted:

.. code-block:: console

    $ openstack network show net1
    +---------------------------+--------------------------------------+
    | Field                     | Value                                |
    +---------------------------+--------------------------------------+
    | admin_state_up            | UP                                   |
    | availability_zone_hints   | zone-1                               |
    |                           | zone-2                               |
    | availability_zones        | zone-1                               |
    |                           | zone-2                               |
    | created_at                | 2016-12-14T06:23:36Z                 |
    | description               |                                      |
    | headers                   |                                      |
    | id                        | ad88e059-e7fa-4cf7-8857-6731a2a3a554 |
    | ipv4_address_scope        | None                                 |
    | ipv6_address_scope        | None                                 |
    | mtu                       | 1450                                 |
    | name                      | net1                                 |
    | port_security_enabled     | True                                 |
    | project_id                | cfd1889ac7d64ad891d4f20aef9f8d7c     |
    | provider:network_type     | vxlan                                |
    | provider:physical_network | None                                 |
    | provider:segmentation_id  | 77                                   |
    | revision_number           | 3                                    |
    | router:external           | Internal                             |
    | shared                    | False                                |
    | status                    | ACTIVE                               |
    | subnets                   |                                      |
    | tags                      | []                                   |
    | updated_at                | 2016-12-14T06:23:37Z                 |
    +---------------------------+--------------------------------------+

.. code-block:: console

    $ openstack router show router1
    +-------------------------+--------------------------------------+
    | Field                   | Value                                |
    +-------------------------+--------------------------------------+
    | admin_state_up          | UP                                   |
    | availability_zone_hints | zone-1                               |
    |                         | zone-2                               |
    | availability_zones      | zone-1                               |
    |                         | zone-2                               |
    | created_at              | 2016-12-14T06:25:40Z                 |
    | description             |                                      |
    | distributed             | False                                |
    | external_gateway_info   | null                                 |
    | flavor_id               | None                                 |
    | ha                      | False                                |
    | headers                 |                                      |
    | id                      | ced10262-6cfe-47c1-8847-cd64276a868c |
    | name                    | router1                              |
    | project_id              | cfd1889ac7d64ad891d4f20aef9f8d7c     |
    | revision_number         | 3                                    |
    | routes                  |                                      |
    | status                  | ACTIVE                               |
    | tags                    | []                                   |
    | updated_at              | 2016-12-14T06:25:40Z                 |
    +-------------------------+--------------------------------------+

.. note::

    The ``availability_zones`` attribute does not have a value until the
    resource is scheduled. Once the Networking service schedules the resource
    to zones according to ``availability_zone_hints``, ``availability_zones``
    shows in which zone the resource is hosted practically. The
    ``availability_zones`` may not match ``availability_zone_hints``. For
    example, even if you specify a zone with ``availability_zone_hints``, all
    agents of the zone may be dead before the resource is scheduled. In
    general, they should match, unless there are failures or there is no
    capacity left in the zone requested.


Availability zone aware scheduler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Network scheduler
-----------------

Set ``AZAwareWeightScheduler`` to ``network_scheduler_driver`` in
``/etc/neutron/neutron.conf`` so that the Networking service schedules a
network according to the availability zone:

.. code-block:: ini

    network_scheduler_driver = neutron.scheduler.dhcp_agent_scheduler.AZAwareWeightScheduler
    dhcp_load_type = networks

The Networking service schedules a network to one of the agents within the
selected zone as with ``WeightScheduler``. In this case, scheduler refers to
``dhcp_load_type`` as well.


Router scheduler
----------------

Set ``AZLeastRoutersScheduler`` to ``router_scheduler_driver`` in file
``/etc/neutron/neutron.conf`` so that the Networking service schedules a router
according to the availability zone:

.. code-block:: ini

    router_scheduler_driver = neutron.scheduler.l3_agent_scheduler.AZLeastRoutersScheduler

The Networking service schedules a router to one of the agents within the
selected zone as with ``LeastRouterScheduler``.


Achieving high availability with availability zone
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Although, the Networking service provides high availability for routers and
high availability and fault tolerance for networks' DHCP services, availability
zones provide an extra layer of protection by segmenting a Networking service
deployment in isolated failure domains. By deploying HA nodes across different
availability zones, it is guaranteed that network services remain available in
face of zone-wide failures that affect the deployment.

This section explains how to get high availability with the availability zone
for L3 and DHCP. You should naturally set above configuration options for the
availability zone.

L3 high availability
--------------------

Set the following configuration options in file ``/etc/neutron/neutron.conf``
so that you get L3 high availability.

.. code-block:: ini

    l3_ha = True
    max_l3_agents_per_router = 3

HA routers are created on availability zones you selected when creating the
router.

DHCP high availability
----------------------

Set the following configuration options in file ``/etc/neutron/neutron.conf``
so that you get DHCP high availability.

.. code-block:: ini

    dhcp_agents_per_network = 2

DHCP services are created on availability zones you selected when creating the
network.
