.. _config-routed-provider-networks:

========================
Routed provider networks
========================

.. note::

   Use of this feature requires the OpenStack client
   version 3.3 or newer.

Before routed provider networks, the Networking service could not present a
multi-segment layer-3 network as a single entity. Thus, each operator typically
chose one of the following architectures:

* Single large layer-2 network
* Multiple smaller layer-2 networks

Single large layer-2 networks become complex at scale and involve significant
failure domains.

Multiple smaller layer-2 networks scale better and shrink failure domains, but
leave network selection to the user. Without additional information, users
cannot easily differentiate these networks.

A routed provider network enables a single provider network to represent
multiple layer-2 networks (broadcast domains) or segments and enables the
operator to present one network to users. However, the particular IP
addresses available to an instance depend on the segment of the network
available on the particular compute node. Neutron port could be associated
with only one network segment, but there is an exception for OVN distributed
services like OVN Metadata.


Similar to conventional networking, layer-2 (switching) handles transit of
traffic between ports on the same segment and layer-3 (routing) handles
transit of traffic between segments.

Each segment requires at least one subnet that explicitly belongs to that
segment. The association between a segment and a subnet distinguishes a
routed provider network from other types of networks. The Networking service
enforces that either zero or all subnets on a particular network associate
with a segment. For example, attempting to create a subnet without a segment
on a network containing subnets with segments generates an error.

The Networking service does not provide layer-3 services between segments.
Instead, it relies on physical network infrastructure to route subnets.
Thus, both the Networking service and physical network infrastructure must
contain configuration for routed provider networks, similar to conventional
provider networks. In the future, implementation of dynamic routing protocols
may ease configuration of routed networks.

Prerequisites
~~~~~~~~~~~~~

Routed provider networks require additional prerequisites over conventional
provider networks. We recommend using the following procedure:

#. Begin with segments. The Networking service defines a segment using the
   following components:

   * Unique physical network name
   * Segmentation type
   * Segmentation ID

   For example, ``provider1``, ``VLAN``, and ``2016``. See the
   `API reference <https://docs.openstack.org/api-ref/network/v2/#segments>`__
   for more information.

   Within a network, use a unique physical network name for each segment which
   enables reuse of the same segmentation details between subnets. For
   example, using the same VLAN ID across all segments of a particular
   provider network. Similar to conventional provider networks, the operator
   must provision the layer-2 physical network infrastructure accordingly.

#. Implement routing between segments.

   The Networking service does not provision routing among segments. The
   operator must implement routing among segments of a provider network.
   Each subnet on a segment must contain the gateway address of the
   router interface on that particular subnet. For example:

   =========== ======= ======================= =====================
   Segment     Version Addresses               Gateway
   =========== ======= ======================= =====================
   segment1    4       203.0.113.0/24          203.0.113.1
   segment1    6       fd00:203:0:113::/64     fd00:203:0:113::1
   segment2    4       198.51.100.0/24         198.51.100.1
   segment2    6       fd00:198:51:100::/64    fd00:198:51:100::1
   =========== ======= ======================= =====================

#. Map segments to compute nodes.

   Routed provider networks imply that compute nodes reside on different
   segments. The operator must ensure that every compute host that is supposed
   to participate in a router provider network has direct connectivity to one
   of its segments.

   =========== ====== ================
   Host        Rack   Physical Network
   =========== ====== ================
   compute0001 rack 1 segment 1
   compute0002 rack 1 segment 1
   ...         ...    ...
   compute0101 rack 2 segment 2
   compute0102 rack 2 segment 2
   compute0102 rack 2 segment 2
   ...         ...    ...
   =========== ====== ================

#. Deploy DHCP agents.

   Unlike conventional provider networks, a DHCP agent cannot support more
   than one segment within a network. The operator must deploy at least one
   DHCP agent per segment. Consider deploying DHCP agents on compute nodes
   containing the segments rather than one or more network nodes to reduce
   node count.

   =========== ====== ================
   Host        Rack   Physical Network
   =========== ====== ================
   network0001 rack 1 segment 1
   network0002 rack 2 segment 2
   ...         ...    ...
   =========== ====== ================

#. Configure communication of the Networking service with the Compute
   scheduler.

   An instance with an interface with an IPv4 address in a routed provider
   network must be placed by the Compute scheduler in a host that has access to
   a segment with available IPv4 addresses. To make this possible, the
   Networking service communicates to the Compute scheduler the inventory of
   IPv4 addresses associated with each segment of a routed provider network.
   The operator must configure the authentication credentials that the
   Networking service will use to communicate with the Compute scheduler's
   placement API. Please see below an example configuration.

   .. note::

      Coordination between the Networking service and the Compute scheduler is
      not necessary for IPv6 subnets as a consequence of their large address
      spaces.

   .. note::

      The coordination between the Networking service and the Compute scheduler
      requires the following minimum API micro-versions.

      * Compute service API: 2.41
      * Placement API: 1.1

Example configuration
~~~~~~~~~~~~~~~~~~~~~

Controller node
---------------

#. Enable the segments service plug-in by appending ``segments`` to the list
   of ``service_plugins`` in the ``neutron.conf`` file on all nodes running the
   ``neutron-server`` service:

   .. code-block:: ini

      [DEFAULT]
      # ...
      service_plugins = ...,segments

#. Add a ``placement`` section to the ``neutron.conf`` file with authentication
   credentials for the Compute service placement API:

   .. code-block:: ini

      [placement]
      www_authenticate_uri = http://192.0.2.72/identity
      project_domain_name = Default
      project_name = service
      user_domain_name = Default
      password = apassword
      username = nova
      auth_url = http://192.0.2.72/identity_admin
      auth_type = password
      region_name = RegionOne

#. Restart the ``neutron-server`` service.

#. (Optional) Configure the Nova scheduler to filter based upon routed network
   host aggregates. Without this option set, once ports are attached to
   instances and have IP addresses assigned, Nova may schedule instances to
   hosts which do not have access to the required segment. See the `Nova
   configuration reference
   <https://docs.openstack.org/nova/latest/configuration/config.html#scheduler.query_placement_for_routed_network_aggregates>`_
   for more information.

Network or compute nodes
------------------------

* Configure the layer-2 agent on each node to map one or more segments to
  the appropriate physical network bridge or interface and restart the
  agent.

Create a routed provider network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following steps create a routed provider network with two segments. Each
segment contains one IPv4 subnet and one IPv6 subnet.

#. Source the administrative project credentials.
#. Create a VLAN provider network which includes a default segment. In this
   example, the network uses the ``provider1`` physical network with VLAN ID
   2016.

   .. code-block:: console

      $ openstack network create --share --provider-physical-network provider1 \
        --provider-network-type vlan --provider-segment 2016 multisegment1
      +---------------------------+--------------------------------------+
      | Field                     | Value                                |
      +---------------------------+--------------------------------------+
      | admin_state_up            | UP                                   |
      | id                        | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 |
      | ipv4_address_scope        | None                                 |
      | ipv6_address_scope        | None                                 |
      | l2_adjacency              | True                                 |
      | mtu                       | 1500                                 |
      | name                      | multisegment1                        |
      | port_security_enabled     | True                                 |
      | provider:network_type     | vlan                                 |
      | provider:physical_network | provider1                            |
      | provider:segmentation_id  | 2016                                 |
      | revision_number           | 1                                    |
      | router:external           | Internal                             |
      | shared                    | True                                 |
      | status                    | ACTIVE                               |
      | subnets                   |                                      |
      | tags                      | []                                   |
      +---------------------------+--------------------------------------+

#. Rename the default segment to ``segment1``.

   .. code-block:: console

      $ openstack network segment list --network multisegment1
      +--------------------------------------+----------+--------------------------------------+--------------+---------+
      | ID                                   | Name     | Network                              | Network Type | Segment |
      +--------------------------------------+----------+--------------------------------------+--------------+---------+
      | 43e16869-ad31-48e4-87ce-acf756709e18 | None     | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 | vlan         |    2016 |
      +--------------------------------------+----------+--------------------------------------+--------------+---------+

   .. code-block:: console

      $ openstack network segment set --name segment1 43e16869-ad31-48e4-87ce-acf756709e18

   .. note::

      This command provides no output.

#. Create a second segment on the provider network. In this example, the
   segment uses the ``provider2`` physical network with VLAN ID 2017.

   .. code-block:: console

      $ openstack network segment create --physical-network provider2 \
        --network-type vlan --segment 2017 --network multisegment1 segment2
      +------------------+--------------------------------------+
      | Field            | Value                                |
      +------------------+--------------------------------------+
      | description      | None                                 |
      | headers          |                                      |
      | id               | 053b7925-9a89-4489-9992-e164c8cc8763 |
      | name             | segment2                             |
      | network_id       | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 |
      | network_type     | vlan                                 |
      | physical_network | provider2                            |
      | revision_number  | 1                                    |
      | segmentation_id  | 2017                                 |
      | tags             | []                                   |
      +------------------+--------------------------------------+

#. Verify that the network contains the ``segment1`` and ``segment2`` segments.

   .. code-block:: console

      $ openstack network segment list --network multisegment1
      +--------------------------------------+----------+--------------------------------------+--------------+---------+
      | ID                                   | Name     | Network                              | Network Type | Segment |
      +--------------------------------------+----------+--------------------------------------+--------------+---------+
      | 053b7925-9a89-4489-9992-e164c8cc8763 | segment2 | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 | vlan         |    2017 |
      | 43e16869-ad31-48e4-87ce-acf756709e18 | segment1 | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 | vlan         |    2016 |
      +--------------------------------------+----------+--------------------------------------+--------------+---------+

#. Create subnets on the ``segment1`` segment. In this example, the IPv4
   subnet uses 203.0.113.0/24 and the IPv6 subnet uses fd00:203:0:113::/64.

   .. code-block:: console

      $ openstack subnet create \
        --network multisegment1 --network-segment segment1 \
        --ip-version 4 --subnet-range 203.0.113.0/24 \
        multisegment1-segment1-v4
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | allocation_pools  | 203.0.113.2-203.0.113.254            |
      | cidr              | 203.0.113.0/24                       |
      | enable_dhcp       | True                                 |
      | gateway_ip        | 203.0.113.1                          |
      | id                | c428797a-6f8e-4cb1-b394-c404318a2762 |
      | ip_version        | 4                                    |
      | name              | multisegment1-segment1-v4            |
      | network_id        | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 |
      | revision_number   | 1                                    |
      | segment_id        | 43e16869-ad31-48e4-87ce-acf756709e18 |
      | tags              | []                                   |
      +-------------------+--------------------------------------+

      $ openstack subnet create \
        --network multisegment1 --network-segment segment1 \
        --ip-version 6 --subnet-range fd00:203:0:113::/64 \
        --ipv6-address-mode slaac multisegment1-segment1-v6
      +-------------------+------------------------------------------------------+
      | Field             | Value                                                |
      +-------------------+------------------------------------------------------+
      | allocation_pools  | fd00:203:0:113::2-fd00:203:0:113:ffff:ffff:ffff:ffff |
      | cidr              | fd00:203:0:113::/64                                  |
      | enable_dhcp       | True                                                 |
      | gateway_ip        | fd00:203:0:113::1                                    |
      | id                | e41cb069-9902-4c01-9e1c-268c8252256a                 |
      | ip_version        | 6                                                    |
      | ipv6_address_mode | slaac                                                |
      | ipv6_ra_mode      | None                                                 |
      | name              | multisegment1-segment1-v6                            |
      | network_id        | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9                 |
      | revision_number   | 1                                    |
      | segment_id        | 43e16869-ad31-48e4-87ce-acf756709e18                 |
      | tags              | []                                                   |
      +-------------------+------------------------------------------------------+

   .. note::

      By default, IPv6 subnets on provider networks rely on physical network
      infrastructure for stateless address autoconfiguration (SLAAC) and
      router advertisement.

#. Create subnets on the ``segment2`` segment. In this example, the IPv4
   subnet uses 198.51.100.0/24 and the IPv6 subnet uses fd00:198:51:100::/64.

   .. code-block:: console

      $ openstack subnet create \
        --network multisegment1 --network-segment segment2 \
        --ip-version 4 --subnet-range 198.51.100.0/24 \
        multisegment1-segment2-v4
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | allocation_pools  | 198.51.100.2-198.51.100.254          |
      | cidr              | 198.51.100.0/24                      |
      | enable_dhcp       | True                                 |
      | gateway_ip        | 198.51.100.1                         |
      | id                | 242755c2-f5fd-4e7d-bd7a-342ca95e50b2 |
      | ip_version        | 4                                    |
      | name              | multisegment1-segment2-v4            |
      | network_id        | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 |
      | revision_number   | 1                                    |
      | segment_id        | 053b7925-9a89-4489-9992-e164c8cc8763 |
      | tags              | []                                   |
      +-------------------+--------------------------------------+

      $ openstack subnet create \
        --network multisegment1 --network-segment segment2 \
        --ip-version 6 --subnet-range fd00:198:51:100::/64 \
        --ipv6-address-mode slaac multisegment1-segment2-v6
      +-------------------+--------------------------------------------------------+
      | Field             | Value                                                  |
      +-------------------+--------------------------------------------------------+
      | allocation_pools  | fd00:198:51:100::2-fd00:198:51:100:ffff:ffff:ffff:ffff |
      | cidr              | fd00:198:51:100::/64                                   |
      | enable_dhcp       | True                                                   |
      | gateway_ip        | fd00:198:51:100::1                                     |
      | id                | b884c40e-9cfe-4d1b-a085-0a15488e9441                   |
      | ip_version        | 6                                                      |
      | ipv6_address_mode | slaac                                                  |
      | ipv6_ra_mode      | None                                                   |
      | name              | multisegment1-segment2-v6                              |
      | network_id        | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9                   |
      | revision_number   | 1                                                      |
      | segment_id        | 053b7925-9a89-4489-9992-e164c8cc8763                   |
      | tags              | []                                                     |
      +-------------------+--------------------------------------------------------+

#. Verify that each IPv4 subnet associates with at least one DHCP agent.

   .. code-block:: console

      $ openstack network agent list --agent-type dhcp --network multisegment1
      +--------------------------------------+------------+-------------+-------------------+-------+-------+--------------------+
      | ID                                   | Agent Type | Host        | Availability Zone | Alive | State | Binary             |
      +--------------------------------------+------------+-------------+-------------------+-------+-------+--------------------+
      | c904ed10-922c-4c1a-84fd-d928abaf8f55 | DHCP agent | compute0001 | nova              | :-)   | UP    | neutron-dhcp-agent |
      | e0b22cc0-d2a6-4f1c-b17c-27558e20b454 | DHCP agent | compute0101 | nova              | :-)   | UP    | neutron-dhcp-agent |
      +--------------------------------------+------------+-------------+-------------------+-------+-------+--------------------+

#. Verify that inventories were created for each segment IPv4 subnet in the
   Compute service placement API (for the sake of brevity, only one of the
   segments is shown in this example).

   .. code-block:: console

      $ SEGMENT_ID=053b7925-9a89-4489-9992-e164c8cc8763
      $ openstack resource provider inventory list $SEGMENT_ID
      +----------------+------------------+----------+----------+-----------+----------+-------+
      | resource_class | allocation_ratio | max_unit | reserved | step_size | min_unit | total |
      +----------------+------------------+----------+----------+-----------+----------+-------+
      | IPV4_ADDRESS   |              1.0 |        1 |        2 |         1 |        1 |    30 |
      +----------------+------------------+----------+----------+-----------+----------+-------+

#. Verify that host aggregates were created for each segment in the Compute
   service (for the sake of brevity, only one of the segments is shown in this
   example).

   .. code-block:: console

      $ openstack aggregate list
      +----+---------------------------------------------------------+-------------------+
      | Id | Name                                                    | Availability Zone |
      +----+---------------------------------------------------------+-------------------+
      | 10 | Neutron segment id 053b7925-9a89-4489-9992-e164c8cc8763 | None              |
      +----+---------------------------------------------------------+-------------------+

#. Launch one or more instances. Each instance obtains IP addresses according
   to the segment it uses on the particular compute node.

   .. note::

      If a fixed IP is specified by the user in the port create request, that
      particular IP is allocated immediately to the port. However, creating a
      port and passing it to an instance yields a different behavior than
      conventional networks. If the fixed IP is not specified on the port
      create request, the Networking service defers assignment of IP
      addresses to the port until the particular compute node becomes
      apparent. For example:

      .. code-block:: console

         $ openstack port create --network multisegment1 port1
         +-----------------------+--------------------------------------+
         | Field                 | Value                                |
         +-----------------------+--------------------------------------+
         | admin_state_up        | UP                                   |
         | binding_vnic_type     | normal                               |
         | id                    | 6181fb47-7a74-4add-9b6b-f9837c1c90c4 |
         | ip_allocation         | deferred                             |
         | mac_address           | fa:16:3e:34:de:9b                    |
         | name                  | port1                                |
         | network_id            | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 |
         | port_security_enabled | True                                 |
         | revision_number       | 1                                    |
         | security_groups       | e4fcef0d-e2c5-40c3-a385-9c33ac9289c5 |
         | status                | DOWN                                 |
         | tags                  | []                                   |
         +-----------------------+--------------------------------------+

Migrating non-routed networks to routed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Migration of existing non-routed networks is only possible if there is only one
segment and one subnet on the network. To migrate a candidate network, update
the subnet and set ``id`` of the existing network segment as ``segment_id``.

.. note::

   In the case where there are multiple subnets or segments it is not
   possible to safely migrate. The reason for this is that in non-routed
   networks addresses from the subnet's allocation pools are assigned to
   ports without considering to which network segment the port is bound.

Example
-------

The following steps migrate an existing non-routed network with one subnet and
one segment to a routed one.

#. Source the administrative project credentials.
#. Get the ``id`` of the current network segment on the network that is being
   migrated.

   .. code-block:: console

      $ openstack network segment list --network my_network
      +--------------------------------------+------+--------------------------------------+--------------+---------+
      | ID                                   | Name | Network                              | Network Type | Segment |
      +--------------------------------------+------+--------------------------------------+--------------+---------+
      | 81e5453d-4c9f-43a5-8ddf-feaf3937e8c7 | None | 45e84575-2918-471c-95c0-018b961a2984 | flat         | None    |
      +--------------------------------------+------+--------------------------------------+--------------+---------+

#. Get the ``id`` or ``name`` of the current subnet on the network.

   .. code-block:: console

      $ openstack subnet list --network my_network
      +--------------------------------------+-----------+--------------------------------------+---------------+
      | ID                                   | Name      | Network                              | Subnet        |
      +--------------------------------------+-----------+--------------------------------------+---------------+
      | 71d931d2-0328-46ae-93bc-126caf794307 | my_subnet | 45e84575-2918-471c-95c0-018b961a2984 | 172.24.4.0/24 |
      +--------------------------------------+-----------+--------------------------------------+---------------+

#. Verify the current ``segment_id`` of the subnet is ``None``.

   .. code-block:: console

      $ openstack subnet show my_subnet --c segment_id
      +------------+-------+
      | Field      | Value |
      +------------+-------+
      | segment_id | None  |
      +------------+-------+

#. Update the ``segment_id`` of the subnet.

   .. code-block:: console

      $ openstack subnet set --network-segment 81e5453d-4c9f-43a5-8ddf-feaf3937e8c7 my_subnet

#. Verify that the subnet is now associated with the desired network segment.

   .. code-block:: console

      $ openstack subnet show my_subnet --c segment_id
      +------------+--------------------------------------+
      | Field      | Value                                |
      +------------+--------------------------------------+
      | segment_id | 81e5453d-4c9f-43a5-8ddf-feaf3937e8c7 |
      +------------+--------------------------------------+


Routed provider networks as external networks for tenant routed networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   This section applies only to legacy routers, not DVR nor HA routers. A
   legacy router has a single instance that is hosted in one single host.

One of the consequences of this feature is the externalization of any routing
operation. The communication (routing) between segments is done using the
underlying network infrastructure, not managed by Neutron.

Could be the case that the user needs to split the communication between
several hosts. It is possible to create tenant networks and connect them using
a router. To access to the routed provider network, it should be connected
as router gateway.

.. code-block:: bash

   Tenant net1  ┌─────────────────────┐
   ─────────────┤                     │
                │                     │ Routed provided network
                │             GW port ├────────────────────────
   Tenant net2  │                     │
   ─────────────┤                     │
                └─────────────────────┘

The routed provider network, acting as router gateway, contains all subnets
associated to the segments. In a deployment without routed provided networks,
the gateway port has L2 connectivity to all subnet CIDRs. In this case, the
gateway port has only connectivity to the attached segment subnets and its
L2 broadcast domains.

The L3 agent will create, inside the router namespace, a default route in the
gateway port fixed IP CIDR. For each other subnet not belonging to the port's
fixed IP address, an onlink route is created. These routes use the gateway port
as routing device and allow to route any packet with destination on these
CIDRs through this port.

The problem in the case of connecting the gatewat port to a routed provider
network is that it will have broadcast connectivity only to those subnets
that belong to the host segment:

* One of those subnets will provide the port IP address. The gateway IP address
  of this subnet will be the default route, through the gateway port.
* Any other subnet belonging to this segment will create a onlink route, using
  the gateway port as route device.

For example, let's consider the following configuration:

* Two tenant networks with CIDRs 10.1.0.0/24 and 10.2.0.0/24.
* A RPN with two segments; each segment with two subnets: segment 1 with
  10.51.0.0/24 and 10.52.0.0/24, segment 2 with 10.53.0.0/24 and 10.54.0.0/24.
* The router is connected to the first segment and the gateway port has an IP
  address in the range of 10.51.0.0/24. This is why the default route uses
  an IP address in this range.

Without considering that the gateway network is a router provided network, this
is the routing table set in the router namespace:

.. code-block:: bash

   $ ip netns exec $r ip r
   default via 10.51.0.1 dev qg-gwport proto static
   10.1.0.0/24 dev qr-tenant1 proto kernel scope link src 10.1.0.1
   10.2.0.0/24 dev qr-tenant2 proto kernel scope link src 10.2.0.1
   10.51.0.0/24 dev qg-gwport proto kernel scope link src 10.100.0.15
   10.52.0.0/24 dev qg-gwport proto static scope link
   10.53.0.0/24 dev qg-gwport proto static scope link  <-- should be removed, belongs to segment 2
   10.54.0.0/24 dev qg-gwport proto static scope link  <-- should be removed, belongs to segment 2

Those packets sent to 10.53.0.0/24 and 10.54.0.0/24 (the second RPN subnet
CIDRs), don't have L2 connectivity and the ARP packets won't be replied. In the
case of having a RPN as gateway network, all packets exiting the router through
the gateway, must be sent to the gateway IP address, in this case 10.51.0.1.
This is why the L3 plugin does not send the information of other segments
subnets L3 agent when:

* The network is the router gateway.
* The "segments" plugin is enabled; this plugin is needed for routed provided
  networks.
* The network is connected to a segment.


Multiple routed provider segments per host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Starting with 2023.1 (Antelope), the support of routed provider networks has
been enhanced to handle multiple segments per host. The main
consequence will be for an operator to extend the IP pool without
creating multiple networks and/or increasing broadcast domain.

.. note::

   The present support is only available for OVS agent at this point.

#. On a given provider network, create a second segment. In this
   example, the second segment uses the ``provider1`` physical network
   with VLAN ID 2020.

   .. code-block:: console

      $ openstack network segment create --physical-network provider1 \
        --network-type vlan --segment 2020 --network multisegment1 segment1-2
      +------------------+--------------------------------------+
      | Field            | Value                                |
      +------------------+--------------------------------------+
      | description      | None                                 |
      | headers          |                                      |
      | id               | 333b7925-9a89-4489-9992-e164c8cc8764 |
      | name             | segment1-2                           |
      | network_id       | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 |
      | network_type     | vlan                                 |
      | physical_network | provider1                            |
      | revision_number  | 1                                    |
      | segmentation_id  | 2020                                 |
      | tags             | []                                   |
      +------------------+--------------------------------------+

#. Create subnets on the ``segment1-2`` segment. In this example, the IPv4
   subnet uses 203.0.114.0/24.

   .. code-block:: console

       $ openstack subnet create \
        --network multisegment1 --network-segment segment1-2 \
        --ip-version 4 --subnet-range 203.0.114.0/24 \
        multisegment1-segment1-2
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | allocation_pools  | 203.0.114.2-203.0.114.254            |
      | cidr              | 203.0.114.0/24                       |
      | enable_dhcp       | True                                 |
      | gateway_ip        | 203.0.114.1                          |
      | id                | c428797a-6f8e-4cb1-b394-c404318a2762 |
      | ip_version        | 4                                    |
      | name              | multisegment1-segment1-2             |
      | network_id        | 6ab19caa-dda9-4b3d-abc4-5b8f435b98d9 |
      | revision_number   | 1                                    |
      | segment_id        | 333b7925-9a89-4489-9992-e164c8cc8764 |
      | tags              | []                                   |
      +-------------------+--------------------------------------+

Considering that, for a subnet of the given provider network
``provider1`` running out of available IP, Neutron will automatically
switch to the subnet ``multisegment1-segment1-2``.
