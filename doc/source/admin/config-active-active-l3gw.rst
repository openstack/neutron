.. _config-active-active-l3gw:

=========================================
Active-active L3 Gateway with Multihoming
=========================================

Why
~~~

By default, Neutron routers are set up with a single external gateway port
connected to a single layer 2 broadcast domain.  To allow layer 3 connectivity
to the outside world, a single static default route is added per address
family, pointing at the IP address provided by the network administrator.

In such a configuration high availability is achieved by ensuring the same
layer 2 broadcast domain is available to all gateway chassis, allowing the
network equipment to be configured to provide the gateway IP as a virtual IP
address serviced by multiple routers.

Providing a single layer 2 broadcast domain to many hosts in a large data
center network can be undesired, this feature may provide a way to implement
external gateway high availability at the layer 3 level.

Both approaches have their benefits and drawbacks, so make sure to familiarize
yourself with the `limitations`_ and `scale considerations`_ before deciding
whether this feature meets your requirements.

Prerequisites
~~~~~~~~~~~~~

The network equipment involved in routing to/from the cloud needs to support
`Bidirectional Forwarding Detection`_ (BFD) for static routes.  For the purpose
of this document we will be using `FRR support for BFD static route
monitoring`_.

There are further requirements for the network equipment acting as border
gateways, which may include provision of direct links, configuration of IGP,
redistribution of static routes and so on, however these details are outside
the scope of this document.

Supported drivers and versions
------------------------------

* OpenStack 2024.1 or newer.
* OVN 22.03 or newer.

.. note::

   At the time of this writing only the ML2/OVN driver supports this feature.

Limitations
-----------

* There is currently no integration with dynamic routing protocols such as BGP
  for this feature, next-hop liveness detection is provided by BFD.
* The feature can not be used together with `Network address translation`_
  (NAT).

.. warning::

   The feature can not be used together with NAT, routers and gateways must be
   created with the ``--disable-snat`` argument, and instances must use site-
   or globally routable addresses.

Scale considerations
--------------------

* Enabling BFD for default routes will establish one BFD session per
  router gateway port.  Each participant in a BFD Session typically transmit
  one message per second.  The BFD Control packets are subject to slow path
  processing and it is advised to ensure the control plane capacity in network
  equipment aligns with the expected number of router gateway ports.

How
~~~

As laid out in the `Active-active L3 Gateway with Multihoming specification`_,
the components involved in achieving high availability at the layer 3 level
are:

* `Adding multiple gateway ports to a router`_, providing interfaces in
  multiple layer 2 broadcast domains and/or layer 3 subnets.
* `Adding multiple default routes to a router`_, each with different output
  port and next-hop addresses, effectively enabling Equal-cost multi-path
  routing (ECMP).
* `Enabling BFD for next-hop liveness detection`_.
* `Avoiding the use of NAT`_.

There are also a set of `use cases`_ with examples below.

Adding multiple gateway ports to a router
-----------------------------------------

A router can be set up with multiple gateway ports at router creation time by
passing multiple ``--external-gateway`` arguments.  You can also specify which
IP address to use by passing the ``--fixed-ip`` with both the ``subnet`` and
``ip-address`` keys populated.  The ``subnet`` provided must be attached to one
of the networks provided to the ``--external-gateway`` arguments.

An existing router can be modified to have multiple gateway ports by using the
``openstack router add gateway`` command with router and network as arguments
and optionally specifying the IP address by passing the ``--fixed-ip``
argument.

By default only one default route will be created.

Adding multiple default routes to a router
------------------------------------------

Whether to create multiple default routes is controlled by the
``enable-default-route-ecmp`` router property.  It can be set per router at
router creation time by passing the ``--enable-default-route-ecmp`` argument or
by updating an existing router using the ``openstack router set`` command.

The default behavior for new routers can be controlled using the
`enable_default_route_ecmp`_ configuration option.

.. note::

   Adding multiple default routes without also `enabling BFD for next-hop
   liveness detection`_ is not recommended, as it will lead to degraded
   performance in the event of failure.

Enabling BFD for next-hop liveness detection
--------------------------------------------

Whether to enable monitoring of next-hop liveness through BFD for default
routes is controlled by the ``enable-default-route-bfd`` router property.  It
can be set per router at router creation time by passing the
``--enable-default-route-bfd`` argument or by updating an existing router using
the ``openstack router set`` command.

The default behavior for new routers can be controlled using the
`enable_default_route_bfd`_ configuration option.

It is recommended to enable this when `adding multiple default routes to a
router`_ as failure to do so will lead to degraded performance in the event of
failure.

Avoiding the use of NAT
-----------------------

OVN relies on connection tracking to keep required state for ongoing
connections to implement NAT, and this state is local to each gateway chassis.

When you set up high availability at the layer 3 level, traffic can take
multiple paths, even individual packets in a single flow.

Packets of an individual flow taking multiple paths does not work well with
the local state of gateway chassis.  To give an example; if traffic from a flow
exits chassis A and then return traffic enters on chassis B, chassis B will not
know to whom the packet belongs when NAT is enabled.

Use cases
~~~~~~~~~

Independent network paths for gateways without need for shared L2
-----------------------------------------------------------------

.. code-block:: console

                     +-------+
                     | spine |
                     +-------+
         +------+                +------+
         | leaf |                | leaf |
         +------+                +------+

    +-----------------+     +-----------------+
    |      rack       |     |      rack       |
    | +-------------+ |     | +-------------+ |
    | | hypervisor  | |     | | hypervisor  | |
    | +-------------+ |     | +-------------+ |
    | | network-gw1 | |     | | network-gw2 | |
    | +-------------+ |     | +-------------+ |
    |     | phy1:net1 |     |     | phy2:net2 |
    | +------------+  |     | +------------+  |
    | | Border GW1 |  |     | | Border GW2 |  |
    | +------------+  |     | +------------+  |
    +-----------------+     +-----------------+

Example
~~~~~~~

First create the external networks:

.. code-block:: console

   $ source openrc admin

   $ openstack network create \
       --external \
       --provider-network-type flat \
       --provider-physical-network phy1 \
       net1

   $ openstack network create \
       --external \
       --provider-network-type flat \
       --provider-physical-network phy2 \
       net2

Then create subnets for the external networks:

.. code-block:: console

   $ source openrc admin

   $ openstack subnet create \
       --subnet-range 192.0.2.0/24 \
       --no-dhcp \
       --network net1 \
       --gateway 192.0.2.2 \
       subnet1

   $ openstack subnet create \
       --subnet-range 198.51.100.0/24 \
       --no-dhcp \
       --network net2 \
       --gateway 198.51.100.2 \
       subnet2

Then create the router with gateway ports in both external networks:

.. code-block:: console

   $ source openrc admin

   $ openstack router create \
       --disable-snat \
       --external-gateway net1 \
       --fixed-ip subnet=subnet1,ip-address=192.0.2.100 \
       --external-gateway net2 \
       --fixed-ip subnet=subnet2,ip-address=198.51.100.100 \
       --enable-default-route-bfd \
       --enable-default-route-ecmp \
       router1

The end user can then create a subnet for use by a project:

.. code-block:: console

   $ source openrc demo

   $ openstack network create project-network

   $ openstack subnet create \
       --subnet-range 203.0.113.0/24 \
       --network project-network \
       project-subnet

And finally attach the project subnet to the router:

.. code-block:: console

   $ source openrc demo

   $ openstack router add subnet router1 project-subnet

The border router configuration might look like this:

.. code-block:: console

   hostname border-router-1
   !
   ip route 203.0.113.0/24 192.0.2.100 bfd
   !
   bfd
    profile default
     transmit-interval 1000
     receive-interval 1000
    exit
    !
    peer 192.0.2.100 local-address 192.0.2.2 interface eth2
     profile default
    exit
    !
   exit
   !
   end

.. code-block:: console

   hostname border-router-2
   !
   ip route 203.0.113.0/24 198.51.100.100 bfd
   !
   bfd
    profile default
     transmit-interval 1000
     receive-interval 1000
    exit
    !
    peer 198.51.100.100 local-address 198.51.100.2 interface eth2
     profile default
    exit
    !
   exit
   !
   end

In a successful configuration the BFD status might look like this:

.. code-block:: console

   $ sudo ovn-nbctl find bfd dst_ip=192.0.2.2
   _uuid               : b7efc8ac-cfd0-4f43-9dd2-2d38baa43571
   detect_mult         : []
   dst_ip              : "192.0.2.2"
   external_ids        : {}
   logical_port        : lrp-ad4ab4e8-1353-4230-8525-5e22fab7277e
   min_rx              : []
   min_tx              : []
   options             : {}
   status              : up

   $ sudo ovn-nbctl find bfd dst_ip=198.51.100.2
   _uuid               : 905f1f69-0901-4d19-bfcb-40729532ff85
   detect_mult         : []
   dst_ip              : "198.51.100.2"
   external_ids        : {}
   logical_port        : lrp-7fd315dc-a76f-4468-86a5-2c65f55153e4
   min_rx              : []
   min_tx              : []
   options             : {}
   status              : up

.. code-block:: console

   border-router-1# sh bfd peer
   BFD Peers:
     peer 192.0.2.100 local-address 192.0.2.2 vrf default interface eth2
       ID: 2436324418
       Remote ID: 300179009
       Active mode
       Status: up
       Uptime: 25 minute(s), 25 second(s)
       Diagnostics: ok
       Remote diagnostics: ok
       Peer Type: configured
       RTT min/avg/max: 0/0/0 usec
       Local timers:
           Detect-multiplier: 3
           Receive interval: 1000ms
           Transmission interval: 1000ms
           Echo receive interval: 50ms
           Echo transmission interval: disabled
       Remote timers:
           Detect-multiplier: 5
           Receive interval: 1000ms
           Transmission interval: 1000ms
           Echo receive interval: disabled

.. code-block:: console

   border-router-2# sh bfd peer
   BFD Peers:
     peer 198.51.100.100 local-address 198.51.100.2 vrf default interface eth2
       ID: 3137653350
       Remote ID: 35580729
       Active mode
       Status: up
       Uptime: 26 minute(s), 2 second(s)
       Diagnostics: ok
       Remote diagnostics: ok
       Peer Type: configured
       RTT min/avg/max: 0/0/0 usec
       Local timers:
           Detect-multiplier: 3
           Receive interval: 1000ms
           Transmission interval: 1000ms
           Echo receive interval: 50ms
           Echo transmission interval: disabled
       Remote timers:
           Detect-multiplier: 5
           Receive interval: 1000ms
           Transmission interval: 1000ms
           Echo receive interval: disabled

Load sharing
------------

Expanding on the above example, load sharing can also be accomplished by adding
multiple gateway ports in each subnet.

Assuming there are enough chassis available, Neutron will make sure to schedule
multiple Logical Router Ports (LRP) for a single router so that different
chassis serve as the primary gateway chassis.

.. code-block:: console

   $ openstack router add gateway \
       --fixed-ip subnet=subnet1,ip-address=192.0.2.101 \
       router1 \
       net1

    $ openstack router add gateway \
        --fixed-ip subnet=subnet2,ip-address=198.51.100.101 \
        router1 \
        net2

.. code-block:: console

   hostname border-router-1
   !
   ip route 203.0.113.0/24 192.0.2.101 bfd
   !
   bfd
    peer 192.0.2.101 local-address 192.0.2.2 interface eth2
     profile default
    exit
    !
   exit
   !
   end

.. code-block:: console

   hostname border-router-2
   !
   ip route 203.0.113.0/24 198.51.100.101 bfd
   !
   bfd
    peer 198.51.100.101 local-address 198.51.100.2 interface eth2
     profile default
    exit
    !
   exit
   !
   end

.. code-block:: console

   $ sudo ovn-nbctl find bfd dst_ip=192.0.2.2
   _uuid               : b7efc8ac-cfd0-4f43-9dd2-2d38baa43571
   detect_mult         : []
   dst_ip              : "192.0.2.2"
   external_ids        : {}
   logical_port        : lrp-ad4ab4e8-1353-4230-8525-5e22fab7277e
   min_rx              : []
   min_tx              : []
   options             : {}
   status              : up

   _uuid               : efbcf3c2-0c34-4fbc-89ed-b742baa25f9b
   detect_mult         : []
   dst_ip              : "192.0.2.2"
   external_ids        : {}
   logical_port        : lrp-7aa481e9-732f-4700-acfb-37de5eb1984a
   min_rx              : []
   min_tx              : []
   options             : {}
   status              : up

   $ sudo ovn-nbctl find bfd dst_ip=198.51.100.2
   _uuid               : 905f1f69-0901-4d19-bfcb-40729532ff85
   detect_mult         : []
   dst_ip              : "198.51.100.2"
   external_ids        : {}
   logical_port        : lrp-7fd315dc-a76f-4468-86a5-2c65f55153e4
   min_rx              : []
   min_tx              : []
   options             : {}
   status              : up

   _uuid               : 2214892e-5df3-47a4-b8e0-24fe7446129c
   detect_mult         : []
   dst_ip              : "198.51.100.2"
   external_ids        : {}
   logical_port        : lrp-2f0aae53-8561-46af-a741-13963368ef2a
   min_rx              : []
   min_tx              : []
   options             : {}
   status              : up

.. code-block:: console

   border-router-1# sh bfd peer
   BFD Peers:
     peer 192.0.2.101 local-address 192.0.2.2 vrf default interface eth2
        ID: 2436324418
        Remote ID: 300179009
        Active mode
        Status: up
        Uptime: 37 minute(s), 54 second(s)
        Diagnostics: ok
        Remote diagnostics: ok
        Peer Type: configured
        RTT min/avg/max: 0/0/0 usec
        Local timers:
            Detect-multiplier: 3
            Receive interval: 1000ms
            Transmission interval: 1000ms
            Echo receive interval: 50ms
            Echo transmission interval: disabled
        Remote timers:
            Detect-multiplier: 5
            Receive interval: 1000ms
            Transmission interval: 1000ms
            Echo receive interval: disabled

     peer 192.0.2.101 local-address 192.0.2.2 vrf default interface eth2
        ID: 295648861
        Remote ID: 877647437
        Active mode
        Status: up
        Uptime: 37 minute(s), 55 second(s)
        Diagnostics: ok
        Remote diagnostics: ok
        Peer Type: configured
        RTT min/avg/max: 0/0/0 usec
        Local timers:
            Detect-multiplier: 3
            Receive interval: 1000ms
            Transmission interval: 1000ms
            Echo receive interval: 50ms
            Echo transmission interval: disabled
        Remote timers:
            Detect-multiplier: 5
            Receive interval: 1000ms
            Transmission interval: 1000ms
            Echo receive interval: disabled

.. code-block:: console

   border-router-2# sh bfd peer
   BFD Peers:
     peer 198.51.100.100 local-address 198.51.100.2 vrf default interface eth2
        ID: 90369368
        Remote ID: 3549983429
        Active mode
        Status: up
        Uptime: 37 minute(s), 57 second(s)
        Diagnostics: ok
        Remote diagnostics: ok
        Peer Type: configured
        RTT min/avg/max: 0/0/0 usec
        Local timers:
            Detect-multiplier: 3
            Receive interval: 1000ms
            Transmission interval: 1000ms
            Echo receive interval: 50ms
            Echo transmission interval: disabled
        Remote timers:
            Detect-multiplier: 5
            Receive interval: 1000ms
            Transmission interval: 1000ms
            Echo receive interval: disabled

     peer 198.51.100.101 local-address 198.51.100.2 vrf default interface eth2
        ID: 3137653350
        Remote ID: 35580729
        Active mode
        Status: up
        Uptime: 37 minute(s), 57 second(s)
        Diagnostics: ok
        Remote diagnostics: ok
        Peer Type: configured
        RTT min/avg/max: 0/0/0 usec
        Local timers:
            Detect-multiplier: 3
            Receive interval: 1000ms
            Transmission interval: 1000ms
            Echo receive interval: 50ms
            Echo transmission interval: disabled
        Remote timers:
            Detect-multiplier: 5
            Receive interval: 1000ms
            Transmission interval: 1000ms
            Echo receive interval: disabled

.. LINKS
.. _FRR support for BFD static route monitoring: https://github.com/FRRouting/frr/pull/12424
.. _Bidirectional Forwarding Detection: https://datatracker.ietf.org/doc/html/rfc5880
.. _Active-active L3 Gateway with Multihoming specification: https://specs.openstack.org/openstack/neutron-specs/specs/2024.1/active-active-l3-gateway-with-multihoming.html
.. _Network address translation: https://docs.openstack.org/neutron/latest/admin/intro-nat.html
.. _enable_default_route_bfd: https://docs.openstack.org/neutron/latest/configuration/neutron.html#DEFAULT.enable_default_route_bfd
.. _enable_default_route_ecmp: https://docs.openstack.org/neutron/latest/configuration/neutron.html#DEFAULT.enable_default_route_ecmp
