.. _config-ipv6:

====
IPv6
====

This section describes the OpenStack Networking reference implementation
for IPv6, including the following items:

* How to enable dual-stack (IPv4 and IPv6 enabled) instances.
* How those instances receive an IPv6 address.
* How those instances communicate across a router to other subnets or
  the internet.
* How those instances interact with other OpenStack services.

Enabling a dual-stack network in OpenStack Networking simply requires
creating a subnet with the ``ip_version`` field set to ``6``, then the
IPv6 attributes (``ipv6_ra_mode`` and ``ipv6_address_mode``) set.  The
``ipv6_ra_mode`` and ``ipv6_address_mode`` will be described in detail in
the next section. Finally, the subnets ``cidr`` needs to be provided.

This section does not include the following items:

* Single stack IPv6 project networking
* OpenStack control communication between servers and services over an IPv6
  network.
* Connection to the OpenStack APIs via an IPv6 transport network
* IPv6 multicast
* IPv6 support in conjunction with any out of tree routers, switches, services
  or agents whether in physical or virtual form factors.

Neutron subnets and the IPv6 API attributes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As of Juno, the OpenStack Networking service (neutron) provides two
new attributes to the subnet object, which allows users of the API to
configure IPv6 subnets.

There are two IPv6 attributes:

* ``ipv6_ra_mode``
* ``ipv6_address_mode``

These attributes can be set to the following values:

* ``slaac``
* ``dhcpv6-stateful``
* ``dhcpv6-stateless``

The attributes can also be left unset.


IPv6 addressing
---------------

The ``ipv6_address_mode`` attribute is used to control how addressing is
handled by OpenStack. There are a number of different ways that guest
instances can obtain an IPv6 address, and this attribute exposes these
choices to users of the Networking API.


Router advertisements
---------------------

The ``ipv6_ra_mode`` attribute is used to control router
advertisements for a subnet.

The IPv6 Protocol uses Internet Control Message Protocol packets
(ICMPv6) as a way to distribute information about networking. ICMPv6
packets with the type flag set to 134 are called "Router
Advertisement" messages, which contain information about the router
and the route that can be used by guest instances to send network
traffic.

The ``ipv6_ra_mode`` is used to specify if the Networking service should
generate Router Advertisement messages for a subnet.

ipv6_ra_mode and ipv6_address_mode combinations
-----------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 10 10 10 10 60

   * - ipv6 ra mode
     - ipv6 address mode
     - neutron-generated advertisements (radvd) A,M,O
     - External Router A,M,O
     - Description
   * - *N/S*
     - *N/S*
     - Off
     - Not Defined
     - Backwards compatibility with pre-Juno IPv6 behavior.
   * - *N/S*
     - slaac
     - Off
     - 1,0,0
     - Guest instance obtains IPv6 address from non-OpenStack router using SLAAC.
   * - *N/S*
     - dhcpv6-stateful
     - Off
     - 0,1,1
     - Not currently implemented in the reference implementation.
   * - *N/S*
     - dhcpv6-stateless
     - Off
     - 1,0,1
     - Not currently implemented in the reference implementation.
   * - slaac
     - *N/S*
     - 1,0,0
     - Off
     - Not currently implemented in the reference implementation.
   * - dhcpv6-stateful
     - *N/S*
     - 0,1,1
     - Off
     - Not currently implemented in the reference implementation.
   * - dhcpv6-stateless
     - *N/S*
     - 1,0,1
     - Off
     - Not currently implemented in the reference implementation.
   * - slaac
     - slaac
     - 1,0,0
     - Off
     - Guest instance obtains IPv6 address from OpenStack managed radvd using SLAAC.
   * - dhcpv6-stateful
     - dhcpv6-stateful
     - 0,1,1
     - Off
     - Guest instance obtains IPv6 address from dnsmasq using DHCPv6
       stateful and optional info from dnsmasq using DHCPv6.
   * - dhcpv6-stateless
     - dhcpv6-stateless
     - 1,0,1
     - Off
     - Guest instance obtains IPv6 address from OpenStack managed
       radvd using SLAAC and optional info from dnsmasq using
       DHCPv6.
   * - slaac
     - dhcpv6-stateful
     -
     -
     - *Invalid combination.*
   * - slaac
     - dhcpv6-stateless
     -
     -
     - *Invalid combination.*
   * - dhcpv6-stateful
     - slaac
     -
     -
     - *Invalid combination.*
   * - dhcpv6-stateful
     - dhcpv6-stateless
     -
     -
     - *Invalid combination.*
   * - dhcpv6-stateless
     - slaac
     -
     -
     - *Invalid combination.*
   * - dhcpv6-stateless
     - dhcpv6-stateful
     -
     -
     - *Invalid combination.*

*A - Autonomous Address Configuration Flag,*
*M - Managed Address Configuration Flag,*
*O - Other Configuration Flag*

Project network considerations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dataplane
---------

Both the Linux bridge and the Open vSwitch dataplane modules support
forwarding IPv6
packets amongst the guests and router ports. Similar to IPv4, there is no
special configuration or setup required to enable the dataplane to properly
forward packets from the source to the destination using IPv6. Note that these
dataplanes will forward Link-local Address (LLA) packets between hosts on the
same network just fine without any participation or setup by OpenStack
components after the ports are all connected and MAC addresses learned.

Addresses for subnets
---------------------

There are three methods currently implemented for a subnet to get its
``cidr`` in OpenStack:

#. Direct assignment during subnet creation via command line or Horizon
#. Referencing a subnet pool during subnet creation
#. Using a Prefix Delegation (PD) client to request a prefix for a
   subnet from a PD server

In the future, additional techniques could be used to allocate subnets
to projects, for example, use of an external IPAM module.

Address modes for ports
-----------------------

.. note::

   An external DHCPv6 server in theory could override the full
   address OpenStack assigns based on the EUI-64 address, but that
   would not be wise as it would not be consistent through the system.

IPv6 supports three different addressing schemes for address configuration and
for providing optional network information.

Stateless Address Auto Configuration (SLAAC)
  Address configuration using Router Advertisements.

DHCPv6-stateless
  Address configuration using Router Advertisements and optional information
  using DHCPv6.

DHCPv6-stateful
  Address configuration and optional information using DHCPv6.

OpenStack can be setup such that OpenStack Networking directly
provides Router Advertisements, DHCP
relay and DHCPv6 address and optional information for their networks
or this can be delegated to external routers and services based on the
drivers that are in use. There are two neutron subnet attributes -
``ipv6_ra_mode`` and ``ipv6_address_mode`` – that determine how IPv6
addressing and network information is provided to project instances:

* ``ipv6_ra_mode``: Determines who sends Router Advertisements.
* ``ipv6_address_mode``: Determines how instances obtain IPv6 address,
  default gateway, or optional information.

For the above two attributes to be effective, ``enable_dhcp`` of the
subnet object must be set to True.

.. warning::

   When updating a network which already has bound ports with a subnet
   in which Autonomous Address Configuration is enabled (Stateless Address
   Auto Configuration, DHCPv6-stateless) the ports  will be updated with
   the new address. This will not happen if the subnet is DHCPv6-stateful.
   The same is true for the case when the ports are bound with an IPv6
   subnet (the network has no other IPv4 subnet), and an IPv4 subnet
   is added later, the ports will not be updated.

   For more details see the bug
   https://bugs.launchpad.net/neutron/+bug/1719806.

   A workaround is to manually update the port with fixed_ips and add the
   subnet in the request.

Using SLAAC for addressing
--------------------------

When using SLAAC, the currently supported combinations for ``ipv6_ra_mode`` and
``ipv6_address_mode`` are as follows.

.. list-table::
   :header-rows: 1
   :widths: 10 10 50

   * - ipv6_ra_mode
     - ipv6_address_mode
     - Result
   * - Not specified.
     - SLAAC
     - Addresses are assigned using EUI-64, and an external router
       will be used for routing.
   * - SLAAC
     - SLAAC
     - Address are assigned using EUI-64, and OpenStack Networking
       provides routing.

Setting SLAAC for ``ipv6_ra_mode`` configures the neutron
router with an radvd agent to send Router Advertisements. The list below
captures the values set for the address configuration flags in the Router
Advertisement messages in this scenario.

* Autonomous Address Configuration Flag = 1
* Managed Address Configuration Flag = 0
* Other Configuration Flag = 0

New or existing neutron networks that contain a SLAAC enabled IPv6 subnet will
result in all neutron ports attached to the network receiving IPv6 addresses.
This is because when Router Advertisement messages are multicast on a
neutron network, they are received by all IPv6 capable ports on the network,
and each port will then configure an IPv6 address based on the
information contained in the Router Advertisement messages. In some cases, an
IPv6 SLAAC address will be added to a port, in addition to other IPv4 and IPv6
addresses that the port already has been assigned.

.. note::

    If a router is not created and added to the subnet, SLAAC addressing will
    not succeed for instances since no Router Advertisement messages will
    be generated.

DHCPv6
------

For DHCPv6, the currently supported combinations are as
follows:

.. list-table::
   :header-rows: 1
   :widths: 10 10 50

   * - ipv6_ra_mode
     - ipv6_address_mode
     - Result
   * - DHCPv6-stateless
     - DHCPv6-stateless
     - Addresses are assigned through Router Advertisements (see SLAAC above)
       and optional information is delivered through DHCPv6.
   * - DHCPv6-stateful
     - DHCPv6-stateful
     - Addresses and optional information are assigned using DHCPv6.

Setting DHCPv6-stateless for ``ipv6_ra_mode`` configures the neutron
router with an radvd agent to send Router Advertisements. The list below
captures the values set for the address configuration flags in the Router
Advertisement messages in this scenario. Similarly, setting DHCPv6-stateless for
``ipv6_address_mode`` configures neutron DHCP implementation to provide
the additional network information.

* Autonomous Address Configuration Flag = 1
* Managed Address Configuration Flag = 0
* Other Configuration Flag = 1

Setting DHCPv6-stateful for ``ipv6_ra_mode`` configures the neutron
router with an radvd agent to send Router Advertisements. The list below
captures the values set for the address configuration flags in the Router
Advertisements messages in this scenario. Similarly, setting DHCPv6-stateful for
``ipv6_address_mode`` configures neutron DHCP implementation to provide
addresses and additional network information through DHCPv6.

* Autonomous Address Configuration Flag = 0
* Managed Address Configuration Flag = 1
* Other Configuration Flag = 1

.. note::

    If a router is not created and added to the subnet, DHCPv6 addressing will
    not succeed for instances since no Router Advertisement messages will
    be generated.

Router support
~~~~~~~~~~~~~~

The behavior of the neutron router for IPv6 is different than for IPv4 in
a few ways.

Internal router ports, that act as default gateway ports for a network, will
share a common port for all IPv6 subnets associated with the network. This
implies that there will be an IPv6 internal router interface with multiple
IPv6 addresses from each of the IPv6 subnets associated with the network and a
separate IPv4 internal router interface for the IPv4 subnet. On the other
hand, external router ports are allowed to have a dual-stack configuration
with both an IPv4 and an IPv6 address assigned to them.

Neutron project networks that are assigned Global Unicast Address (GUA)
prefixes and addresses don't require NAT on the neutron router external gateway
port to access the outside world. As a consequence of the lack of NAT the
external router port doesn't require a GUA to send and receive to the external
networks. This implies a GUA IPv6 subnet prefix is not necessarily needed for
the neutron external network. By default, a IPv6 LLA associated with the
external gateway port can be used for routing purposes. To handle this
scenario, the implementation of router-gateway-set API in neutron has been
modified so that an IPv6 subnet is not required for the external network that
is associated with the neutron router. The LLA address of the upstream router
can be learned in two ways.

#. In the absence of an upstream Router Advertisement message, the
   ``ipv6_gateway`` flag can be set
   with the external router gateway LLA in the neutron L3 agent configuration
   file. This also requires that no subnet is associated with that port.
#. The upstream router can send a Router Advertisement and the neutron router
   will automatically learn the next-hop LLA, provided again that no subnet is
   assigned and the ``ipv6_gateway`` flag is not set.

Effectively the ``ipv6_gateway`` flag takes precedence over a Router
Advertisements that is received from the upstream router. If it is desired to
use a GUA next hop that is accomplished by allocating a subnet to the external
router port and assigning the upstream routers GUA address as the
gateway for the subnet.

.. note::

   It should be possible for projects to communicate with each other
   on an isolated network (a network without a router port) using LLA
   with little to no participation on the part of OpenStack. The authors
   of this section have not proven that to be true for all scenarios.

.. note::

   When using the neutron L3 agent in a configuration where it is
   auto-configuring an IPv6 address via SLAAC, and the agent is
   learning its default IPv6 route from the ICMPv6 Router Advertisement,
   it may be necessary to set the
   ``net.ipv6.conf.<physical_interface>.accept_ra`` sysctl to the
   value ``2`` in order for routing to function correctly.
   For a more detailed description, please see the `bug <https://bugs.launchpad.net/neutron/+bug/1616282>`__.


Neutron's Distributed Router feature and IPv6
---------------------------------------------

IPv6 does work when the Distributed Virtual Router functionality is enabled,
but all ingress/egress traffic is via the centralized router (hence, not
distributed). More work is required to fully enable this functionality.


Advanced services
~~~~~~~~~~~~~~~~~

VPNaaS
------

VPNaaS supports IPv6, but support in Kilo and prior releases will have
some bugs that may limit how it can be used. More thorough and
complete testing and bug fixing is being done as part of the Liberty
release. IPv6-based VPN-as-a-Service is configured similar to the IPv4
configuration. Either or both the ``peer_address`` and the
``peer_cidr`` can specified as an IPv6 address. The choice of
addressing modes and router modes described above should not impact
support.

FWaaS
-----

FWaaS allows creation of IPv6 based rules.

NAT & Floating IPs
------------------

At the current time OpenStack Networking does not provide any facility
to support any flavor of NAT with IPv6. Unlike IPv4 there is no
current embedded support for floating IPs with IPv6. It is assumed
that the IPv6 addressing amongst the projects is using GUAs with no
overlap across the projects.

Security considerations
~~~~~~~~~~~~~~~~~~~~~~~

For more information about security considerations, see the ``Security groups``
section in
:doc:`intro-os-networking`.

Configuring interfaces of the guest
-----------------------------------

OpenStack currently doesn't support the Privacy Extensions defined by RFC 4941,
or the Opaque Identifier generation methods defined in RFC 7217. The interface
identifier and DUID used must be directly derived from the MAC address
as described in RFC 2373. The compute instances must not be set up to utilize
either of these methods when generating their interface identifier, or
they might not be able to communicate properly on the network. For example,
in Linux guests, these are controlled via these two ``sysctl`` variables:

- ``net.ipv6.conf.*.use_tempaddr`` (Privacy Extensions)

This allows the use of non-changing interface identifiers for IPv6 addresses
according to RFC3041 semantics. It should be disabled (zero) so that stateless
addresses are constructed using a stable, EUI64-based value.

- ``net.ipv6.conf.*.addr_gen_mode``

This defines how link-local and auto-configured IPv6 addresses are
generated. It should be set to zero (default) so that IPv6
addresses are generated using an EUI64-based value.

.. note::

   Support for ``addr_gen_mode`` was added in kernel version 4.11.


Other types of guests might have similar configuration options, please
consult your distribution documentation for more information.

Unlike IPv4, the MTU of a given network can be conveyed in both the Router
Advertisement messages sent by the router, as well as in DHCP messages.

OpenStack control & management network considerations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As of the Kilo release, considerable effort has gone in to ensuring
the project network can handle dual stack IPv6 and IPv4 transport
across the variety of configurations described above. OpenStack control
network can be run in a dual stack configuration and OpenStack API
endpoints can be accessed via an IPv6 network. At this time, Open vSwitch
(OVS) tunnel types - STT, VXLAN, GRE, support both IPv4 and IPv6 endpoints.


.. _prefix-delegation:

Prefix delegation
~~~~~~~~~~~~~~~~~

.. warning::

   This feature is experimental with low test coverage, and the Dibbler client
   which is used for this feature is no longer maintained. For details see:
   https://github.com/tomaszmrugalski/dibbler#project-status

From the Liberty release onwards, OpenStack Networking supports IPv6 prefix
delegation. This section describes the configuration and workflow steps
necessary to use IPv6 prefix delegation to provide automatic allocation of
subnet CIDRs. This allows you as the OpenStack administrator to rely on an
external (to the OpenStack Networking service) DHCPv6 server to manage your
project network prefixes.

.. note::

   Prefix delegation became available in the Liberty release, it is
   not available in the Kilo release. HA and DVR routers
   are not currently supported by this feature.

Configuring OpenStack Networking for prefix delegation
------------------------------------------------------

To enable prefix delegation, edit the ``/etc/neutron/neutron.conf`` file.

.. code-block:: console

   ipv6_pd_enabled = True

.. note::

   If you are not using the default dibbler-based driver for prefix
   delegation, then you also need to set the driver in
   ``/etc/neutron/neutron.conf``:

   .. code-block:: console

      pd_dhcp_driver = <class path to driver>

   Drivers other than the default one may require extra configuration.

This tells OpenStack Networking to use the prefix delegation mechanism for
subnet allocation when the user does not provide a CIDR or subnet pool id when
creating a subnet.

Requirements
------------

To use this feature, you need a prefix delegation capable DHCPv6 server that is
reachable from your OpenStack Networking node(s). This could be software
running on the OpenStack Networking node(s) or elsewhere, or a physical router.
For the purposes of this guide we are using the open-source DHCPv6 server,
Dibbler. Dibbler is available in many Linux package managers, or from source at
`tomaszmrugalski/dibbler <https://github.com/tomaszmrugalski/dibbler>`_.

When using the reference implementation of the OpenStack Networking prefix
delegation driver, Dibbler must also be installed on your OpenStack Networking
node(s) to serve as a DHCPv6 client. Version 1.0.1 or higher is required.

This guide assumes that you are running a Dibbler server on the network node
where the external network bridge exists. If you already have a prefix
delegation capable DHCPv6 server in place, then you can skip the following
section.

Configuring the Dibbler server
------------------------------

After installing Dibbler, edit the ``/etc/dibbler/server.conf`` file:

.. code-block:: none

    script "/var/lib/dibbler/pd-server.sh"

    iface "br-ex" {
        pd-class {
            pd-pool 2001:db8:2222::/48
            pd-length 64
        }
    }

The options used in the configuration file above are:

- ``script``
  Points to a script to be run when a prefix is delegated or
  released. This is only needed if you want instances on your
  subnets to have external network access. More on this below.
- ``iface``
  The name of the network interface on which to listen for
  prefix delegation messages.
- ``pd-pool``
  The larger prefix from which you want your delegated
  prefixes to come. The example given is sufficient if you do
  not need external network access, otherwise a unique
  globally routable prefix is necessary.
- ``pd-length``
  The length that delegated prefixes will be. This must be
  64 to work with the current OpenStack Networking reference implementation.

To provide external network access to your instances, your Dibbler server also
needs to create new routes for each delegated prefix. This is done using the
script file named in the config file above. Edit the
``/var/lib/dibbler/pd-server.sh`` file:

.. code-block:: bash

   if [ "$PREFIX1" != "" ]; then
       if [ "$1" == "add" ]; then
           sudo ip -6 route add ${PREFIX1}/64 via $REMOTE_ADDR dev $IFACE
       fi
       if [ "$1" == "delete" ]; then
           sudo ip -6 route del ${PREFIX1}/64 via $REMOTE_ADDR dev $IFACE
       fi
   fi

The variables used in the script file above are:

- ``$PREFIX1``
  The prefix being added/deleted by the Dibbler server.
- ``$1``
  The operation being performed.
- ``$REMOTE_ADDR``
  The IP address of the requesting Dibbler client.
- ``$IFACE``
  The network interface upon which the request was received.

The above is all you need in this scenario, but more information on
installing, configuring, and running Dibbler is available in the Dibbler user
guide, at `Dibbler – a portable DHCPv6
<http://klub.com.pl/dhcpv6/doc/dibbler-user.pdf>`_.

To start your Dibbler server, run:

.. code-block:: console

   # dibbler-server run

Or to run in headless mode:

.. code-block:: console

   # dibbler-server start

When using DevStack, it is important to start your server after the
``stack.sh`` script has finished to ensure that the required network
interfaces have been created.

User workflow
-------------

First, create a network and IPv6 subnet:

.. code-block:: console

   $ openstack network create ipv6-pd
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | UP                                   |
   | availability_zone_hints   |                                      |
   | availability_zones        |                                      |
   | created_at                | 2017-01-25T19:26:01Z                 |
   | description               |                                      |
   | headers                   |                                      |
   | id                        | 4b782725-6abe-4a2d-b061-763def1bb029 |
   | ipv4_address_scope        | None                                 |
   | ipv6_address_scope        | None                                 |
   | mtu                       | 1450                                 |
   | name                      | ipv6-pd                              |
   | port_security_enabled     | True                                 |
   | project_id                | 61b7eba037fd41f29cfba757c010faff     |
   | provider:network_type     | vxlan                                |
   | provider:physical_network | None                                 |
   | provider:segmentation_id  | 46                                   |
   | revision_number           | 3                                    |
   | router:external           | Internal                             |
   | shared                    | False                                |
   | status                    | ACTIVE                               |
   | subnets                   |                                      |
   | tags                      | []                                   |
   | updated_at                | 2017-01-25T19:26:01Z                 |
   +---------------------------+--------------------------------------+

   $ openstack subnet create --ip-version 6 --ipv6-ra-mode slaac \
   --ipv6-address-mode slaac --use-default-subnet-pool \
   --network ipv6-pd ipv6-pd-1
   +------------------------+--------------------------------------+
   | Field                  | Value                                |
   +------------------------+--------------------------------------+
   | allocation_pools       | ::2-::ffff:ffff:ffff:ffff            |
   | cidr                   | ::/64                                |
   | created_at             | 2017-01-25T19:31:53Z                 |
   | description            |                                      |
   | dns_nameservers        |                                      |
   | enable_dhcp            | True                                 |
   | gateway_ip             | ::1                                  |
   | headers                |                                      |
   | host_routes            |                                      |
   | id                     | 1319510d-c92c-4532-bf5d-8bcf3da761a1 |
   | ip_version             | 6                                    |
   | ipv6_address_mode      | slaac                                |
   | ipv6_ra_mode           | slaac                                |
   | name                   | ipv6-pd-1                            |
   | network_id             | 4b782725-6abe-4a2d-b061-763def1bb029 |
   | project_id             | 61b7eba037fd41f29cfba757c010faff     |
   | revision_number        | 2                                    |
   | service_types          |                                      |
   | subnetpool_id          | prefix_delegation                    |
   | tags                   | []                                   |
   | updated_at             | 2017-01-25T19:31:53Z                 |
   | use_default_subnetpool | True                                 |
   +------------------------+--------------------------------------+

The subnet is initially created with a temporary CIDR before one can be
assigned by prefix delegation. Any number of subnets with this temporary CIDR
can exist without raising an overlap error. The subnetpool_id is automatically
set to ``prefix_delegation``.

To trigger the prefix delegation process, create a router interface between
this subnet and a router with an active interface on the external network:

.. code-block:: console

    $ openstack router add subnet router1 ipv6-pd-1

The prefix delegation mechanism then sends a request via the external network
to your prefix delegation server, which replies with the delegated prefix. The
subnet is then updated with the new prefix, including issuing new IP addresses
to all ports:

.. code-block:: console

    $ openstack subnet show ipv6-pd-1
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | allocation_pools  | 2001:db8:2222:6977::2-2001:db8:2222: |
    |                   | 6977:ffff:ffff:ffff:ffff             |
    | cidr              | 2001:db8:2222:6977::/64              |
    | created_at        | 2017-01-25T19:31:53Z                 |
    | description       |                                      |
    | dns_nameservers   |                                      |
    | enable_dhcp       | True                                 |
    | gateway_ip        | 2001:db8:2222:6977::1                |
    | host_routes       |                                      |
    | id                | 1319510d-c92c-4532-bf5d-8bcf3da761a1 |
    | ip_version        | 6                                    |
    | ipv6_address_mode | slaac                                |
    | ipv6_ra_mode      | slaac                                |
    | name              | ipv6-pd-1                            |
    | network_id        | 4b782725-6abe-4a2d-b061-763def1bb029 |
    | project_id        | 61b7eba037fd41f29cfba757c010faff     |
    | revision_number   | 4                                    |
    | service_types     |                                      |
    | subnetpool_id     | prefix_delegation                    |
    | tags              | []                                   |
    | updated_at        | 2017-01-25T19:35:26Z                 |
    +-------------------+--------------------------------------+


If the prefix delegation server is configured to delegate globally routable
prefixes and setup routes, then any instance with a port on this subnet should
now have external network access.

Deleting the router interface causes the subnet to be reverted to the temporary
CIDR, and all ports have their IPs updated. Prefix leases are released and
renewed automatically as necessary.

References
----------

The following presentation from the Barcelona Summit provides a great guide for
setting up IPv6 with OpenStack: `Deploying IPv6 in OpenStack Environments
<https://www.youtube.com/watch?v=j5hy11YlSOU>`_.
