.. _data-center-networks:

====================
Data Center Networks
====================

In a typical data center deployment, multiple cabinets contain baremetal
servers, with each cabinet having one or more switches that connect to the
baremetal servers. When utilizing OpenStack these servers can make up your
control plane (where OpenStack APIs and services run) or data plane (your
hypervisors for Nova or baremetal for Ironic) nodes. In many cases the lower
layers of the network stack (physical, data link, network, and transport
layers) for OpenStack deployers and operators are not very interesting to
them and are possibly statically configured or provided to them.

However it is becoming increasingly common to have this be more dynamic or
in the case of OpenStack Ironic need to configure these layers via OpenStack
to have a fully automated and interconnected system. It is these cases that
this document is for.

Document Scope
~~~~~~~~~~~~~~

Dynamic network configuration for baremetal servers using ML2 mechanism drivers
has been an established practice in production data centers for years,
including for automating hypervisor provisioning and integrating with existing
SDN infrastructure.

This document covers:

* **Established capabilities**:

  * VLAN-based aggregation zones for baremetal servers using ML2 mechanism
    drivers (e.g., networking-generic-switch, networking-baremetal, and
    vendor-specific drivers)
  * VXLAN overlay networks for virtual machines
  * Integration with existing SDN infrastructure through ML2 plugins

* **Emerging capabilities**:

  * VXLAN overlay network support for baremetal servers through VXLAN-to-VLAN
    translation (EVPN L2VNI). This functionality is currently available through
    out-of-tree vendor-specific ML2 mechanism drivers. The in-tree EVPN L2VNI
    mechanism driver, which provides a vendor-agnostic reference
    implementation, is currently under review for inclusion in Neutron.

Terminology
~~~~~~~~~~~

ToR / Top of Rack Switch
    A switch that is located inside of a cabinet of baremetal servers. It does
    not have to be physically at the top. Often there are multiple forming a
    Multi-Chassis Link Aggregation pair.

Multi-Chassis Link Aggregation (MLAG)
    This is a pair of switches acting together to provide LACP. In terms of
    OVS/OVN, this is the HA Chassis while other vendors will use terms like vPC
    (Virtual Port Channel) or VLT (Virtual Link Trunking).

Aggregation Zone
    A system of switches connected in a north-south hierarchy where typically
    VLANs are utilized to provide tenant or traffic separation.

Fabric
    A system of interconnected switches designed to behave like a single,
    unified network that emphasizes east-west scalability and uniform latency
    utilizing a tunneling protocol such as VXLAN.

VXLAN overlay
    A virtual layer 2 network that runs on top of a layer 3 network, which is
    called the underlay. The overlay utilizes VNIs to provide logical layer 2
    for attached hosts. The underlay provides IP connectivity between VXLAN
    tunnel endpoints (VTEPs). VTEP functionality may be provided through
    virtual network interfaces or dedicated physical hardware to transport
    layer 2 frames across the layer 3 network.

L2VNI
    A logically separated layer 2 broadcast domain which allows all attached
    hosts to communicate as if they were on the same LAN. VNIs must be mapped
    1:1 with a VLAN on a leaf switch to provide connectivity for a host.

L3VNI
    A virtually routed layer 3 segment inside of a VXLAN overlay. This enables
    inter-VNI routing or routing between different L2VNIs. A L3VNI is typically
    associated with a VRF to provide logical isolation between traffic. Often
    times different cabinets are their own segments or L3VNIs.


Current State of Neutron
~~~~~~~~~~~~~~~~~~~~~~~~

Current as of 2025.2

Neutron has long supported all of these networking designs for virtual machines
by utilizing virtual switches. In this case when utilizing VXLAN, Neutron is
creating its own Fabric where each Compute Node that is running OVS is acting
as a ToR. This Fabric is unrelated and completely separate from the
Fabric that is making up the physical switches providing connectivity.

Neutron has supported modeling and configuration of an Aggregation Zone with the
ML2 VLAN type and it even supports multiple Aggregation Zones by utilizing the
``provider:physical_network`` field on the network. Ironic is able to have
baremetal servers in multiple Aggregation Zones by utilizing the
``physical_network`` field on Ironic's Port or Portgroup objects which
represent a physical Ethernet
port for the former and a Link Aggregation for the latter. There exist multiple
out of tree ML2 mechanism drivers that are vendor specific that support
configuring these baremetal switches with the reference implementation used by
OpenStack in testing being
`networking-generic-switch <https://docs.openstack.org/networking-generic-switch/latest/>`_.

When it comes to VXLAN, virtual machines are able to participate directly in
a VXLAN overlay through the use of Open vSwitch which creates ports that can be
plugged directly to the virtual machine. In the case of baremetal servers, they
rely on the Top of Rack (ToR) switch to handle the VXLAN-to-VLAN translation by
creating a binding from VXLAN VNI to a VLAN and then configuring the physical
switch port to utilize that VLAN. Overall this allows for
baremetal servers to benefit from the scalability and flexibility of VXLAN
networks while maintaining direct physical network connectivity.

.. note::

   VLAN-to-VNI binding considerations:

   * VLANs bound to a VNI do not have to be the same across the Fabric. This
     allows for theoretical increase in logical layer 2 networks greater than
     4096 that would be the limit for pure VLAN.
   * When utilizing MLAG, the same VLAN must be bound to the VNI for both ports
     making up the LACP link.
   * Due to certain vendor limitations, if multiple ports on the same switch
     need to bind to the same VNI then only one VNI to VLAN binding can be
     created and all ports need to utilize the same VLAN.

To address some of these layer-3 routing use cases, Neutron added
:ref:`Routed Provider Networks <config-routed-provider-networks>`
which can be used to model L3VNI with each segment being tied to one subnet.
While L2VNI is referenced briefly in that documentation as "L2 adjacency," the
rest of this document provides a more comprehensive explanation of how L2VNI
networks work with baremetal servers.

Physical layout
---------------

.. code-block:: text

   ┌─────────────────────────────────────────────────────────────────┐
   │                      Spine/Core Network                         │
   │                   (VXLAN Overlay - VNI 10000)                   │
   └────────────────┬──────────────────────┬─────────────────────────┘
                    │                      │
           Cabinet 1│             Cabinet 2│
         ┌──────────┴─────────┐  ┌─────────┴──────────┐
         │   ToR Switch 1     │  │   ToR Switch 2     │
         │    (physnet1)      │  │    (physnet2)      │
         │                    │  │                    │
         │  VXLAN VNI 10000   │  │  VXLAN VNI 10000   │
         │        ↕           │  │        ↕           │
         │   VLAN 100         │  │   VLAN 105         │
         └─┬────────┬─────────┘  └─┬────────┬─────────┘
           │        │              │        │
      ┌────┴──┐ ┌───┴────┐     ┌───┴────┐  ┌┴────────┐
      │Server1│ │Server2 │     │Server3 │  │Server4  │
      │ eth0  │ │ eth0   │     │ eth0   │  │ eth0    │
      └───────┘ └────────┘     └────────┘  └─────────┘
       VLAN 100   VLAN 100      VLAN 105    VLAN 105

In this architecture:

* **VXLAN VNI 10000** is the overlay network identifier used for the
  virtual network
* **Spine/Core Network** carries only VXLAN-encapsulated traffic; no VLANs or
  native VLAN tagged traffic exists at this layer
* **VLAN 100** is the local VLAN ID assigned on Switch 1 (``physnet1``)
* **VLAN 105** is the local VLAN ID assigned on Switch 2 (``physnet2``)
* Each ToR switch performs VXLAN encapsulation/decapsulation, mapping
  VNI 10000 to VLAN 100 or 105 on the server-facing ports
* Servers in different cabinets can communicate through the VXLAN overlay
  while using local VLAN tagging or as the native VLAN if configured as such.

.. note::

   If the VLAN is not configured as the native VLAN or access VLAN then the
   server must perform tagging. When using Nova to provision Ironic servers,
   Nova will not supply the VLAN information via configdrive or metadata
   API service. See `Expose vlan trunking in metadata/configdrive
   <https://review.opendev.org/c/openstack/nova-specs/+/471815>`_ and
   `Add trunk info to metadata/configdrive
   <https://review.opendev.org/c/openstack/nova/+/941227>`_ for a spec
   and implementation to extend Nova.


.. note::

   In production deployments, ToR switches are often deployed in VPC (Virtual
   Port Channel) pairs for redundancy. Each MLAG pair acts as a single logical
   VTEP (VXLAN Tunnel Endpoint), providing high availability and load
   distribution across both switches. Both switches in the MLAG pair would
   need to be identified by the same identifier like ``physnet1`` in the
   above example.

Binding levels
--------------

.. note::

   The EVPN L2VNI mechanism driver mentioned here is currently in proposal to
   be added to Neutron. For this to work it would to be enabled
   in the ML2 plugin configuration for your Neutron.

.. note::

   Some vendor ML2 mechanism drivers implement this functionality themselves
   as well.


The EVPN L2VNI mechanism driver creates hierarchical port bindings with
multiple levels:

.. code-block:: text

   Neutron Port (Baremetal)
        │
        ├─ Level 1: VXLAN Segment (VNI 10000)
        │           Bound by: evpn-l2vni driver
        │
        └─ Level 2: VLAN Segment (VLAN 100, ``physnet1``)
                    Bound by: networking-generic-switch or
                              networking-baremetal driver

The EVPN L2VNI driver performs a partial binding at the VXLAN level and
creates (or reuses) a dynamic VLAN segment for the lower-level binding.
A subsequent mechanism driver (such as networking-generic-switch) completes
the binding by configuring the physical switch port.

Network segments in detail
---------------------------

When using EVPN VXLAN networks, Neutron creates multiple network segments:

#. **VXLAN Segment** (fabric-wide)

   * Type: ``vxlan``
   * Segmentation ID: VNI number (e.g., 10000)
   * Scope: Entire fabric across all cabinets
   * This can be specified when creating a provider network or can be assigned
     from the network segment range pool.

#. **VLAN Segments** (per physical network)

   * Type: ``vlan``
   * Segmentation ID: Switch-local VLAN number (e.g., 100, 101, 102)
   * Scope: Local to a specific physical network (VPC pair/cabinet)
   * Created dynamically during port binding as needed
   * Multiple ports on the same physical network share the same VLAN segment

This two-tier approach allows:

* A single logical network (VNI) to span multiple physical locations
* Local VLAN assignments that are unique per physical network
* Efficient VLAN ID reuse across different physical networks

.. code-block:: console

   $ openstack network segment list --network baremetal-net
   +--------------------------------------+----------+--------------+---------------+
   | ID                                   | Name     | Network Type | Segment ID    |
   +--------------------------------------+----------+--------------+---------------+
   | a1b2c3d4-e5f6-4a5b-8c7d-9e8f7a6b5c4d | None     | vxlan        | 10000         |
   | b2c3d4e5-f6a7-5b8c-9d7e-0f8a7b6c5d4e | physnet1 | vlan         | 100           |
   | c3d4e5f6-a7b8-6c9d-0e8f-1a9b8c7d6e5f | physnet2 | vlan         | 105           |
   +--------------------------------------+----------+--------------+---------------+

Prerequisites
~~~~~~~~~~~~~

EVPN VXLAN networks for baremetal servers require the following prerequisites:

#. **ML2 plugin configuration**

   Enable the EVPN L2VNI mechanism driver in the ML2 plugin configuration.
   The driver must be listed before other mechanism drivers that will complete
   the port binding (such as networking-generic-switch).

   .. code-block:: ini

      [ml2]
      mechanism_drivers = evpn-l2vni,networking-generic-switch

#. **Physical network infrastructure**

   * Top-of-Rack switches that support VXLAN-to-VLAN mapping (EVPN
     capabilities)
   * BGP EVPN configuration on the switches for VXLAN overlay network
     participation
   * Connectivity between switches for VXLAN tunneling

#. **Neutron network segment ranges**

   :ref:`Network Segment Ranges <config-network-segment-ranges>`
   would need to be configured for this to work from end to end. The ``vxlan``
   segment range is necessary for users to create tenant networks. While the
   ``vlan`` segment ranges are necessary for each MLAG pair of ToR switches.
   An example of ranges which would be compatible with the other example in
   this document would be:

   .. code-block:: console

      $ openstack network segment range list
      +--------------------------------------+----------+---------+--------+------------+--------------+------------------+------------+------------+
      | ID                                   | Name     | Default | Shared | Project ID | Network Type | Physical Network | Minimum ID | Maximum ID |
      +--------------------------------------+----------+---------+--------+------------+--------------+------------------+------------+------------+
      | 0c267189-bf5b-4b8a-afa3-1b22fac9bdd9 | physnet1 | False   | True   | None       | vlan         | physnet1         |        100 |        200 |
      | 1f6d7d40-26c9-4bf5-bfd4-ceb48f5035b6 | physnet2 | False   | True   | None       | vlan         | physnet2         |        105 |        200 |
      | 351ba77c-5b4e-4f65-ab4a-46efd481cf5f | None     | False   | True   | None       | vxlan        | None             |      10000 |      20000 |
      +--------------------------------------+----------+---------+--------+------------+--------------+------------------+------------+------------+

#. **Ironic baremetal nodes**

   Baremetal nodes must be configured with the physical network information
   in their port's ``physical_network`` data, which `Ironic passes to
   Neutron during port binding <https://review.opendev.org/c/openstack/ironic/+/964570>`_.

   .. code-block:: console

      $ openstack baremetal  port list --node node1 --long -c Address -c 'Local Link Connection' -c 'Physical Network'
      +-------------------+------------------------------------------------------------------------------------------------+------------------+
      | Address           | Local Link Connection                                                                          | Physical Network |
      +-------------------+------------------------------------------------------------------------------------------------+------------------+
      | d4:04:e6:4f:71:28 | {'switch_id': 'c4:7e:e0:e4:55:3f', 'port_id': 'Ethernet1/4', 'switch_info': 'physnet1-1.mydc'} | physnet1         |
      | d4:04:e6:4f:71:29 | {'switch_id': '40:14:82:81:3e:e3', 'port_id': 'Ethernet1/4', 'switch_info': 'physnet1-1.mydc'} | physnet1         |
      | 14:23:f3:f4:c7:e0 | {'switch_id': 'c4:7e:e0:e4:03:37', 'port_id': 'Ethernet1/4', 'switch_info': 'physnet1-2.mydc'} | physnet1         |
      | 14:23:f3:f4:c7:e1 | {'switch_id': 'c4:7e:e0:e7:a0:37', 'port_id': 'Ethernet1/4', 'switch_info': 'physnet1-2.mydc'} | physnet1         |
      +-------------------+------------------------------------------------------------------------------------------------+------------------+

#. **Switch configuration drivers**

   A mechanism driver that can configure physical switches, such as:

   * networking-generic-switch
   * networking-baremetal
   * vendor-specific ML2 drivers

Packet flow example
-------------------

Here's a detailed example of traffic flowing from Server A in Cabinet 1 to
Server B in Cabinet 2:

.. code-block:: text

   Server A (Cabinet 1)
      ↓ Sends frame tagged VLAN 100
   ToR Switch 1 (VPC pair, Cabinet 1)
      ↓ Maps VLAN 100 → VNI 10000
      ↓ VXLAN encapsulation
   Spine Network
      ↓ VXLAN tunnel (VNI 10000)
   ToR Switch 2 (VPC pair, Cabinet 2)
      ↓ VXLAN decapsulation
      ↓ Maps VNI 10000 → VLAN 105
      ↓ Sends frame tagged VLAN 105
   Server B (Cabinet 2)

The MAC address learning and forwarding is handled by the EVPN control plane
using BGP, which distributes MAC address reachability information across all
VTEPs in the fabric.

How it works
~~~~~~~~~~~~

Network creation
----------------

When creating a network for EVPN VXLAN baremetal connectivity, you create
a standard VXLAN network (as a tenant or provider):

.. code-block:: console

   $ openstack network create baremetal-net
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | UP                                   |
   | id                        | a1b2c3d4-e5f6-4a5b-8c7d-9e8f7a6b5c4d |
   | name                      | baremetal-net                        |
   | provider:network_type     | vxlan                                |
   | provider:physical_network | None                                 |
   | provider:segmentation_id  | 10000                                |
   | shared                    | False                                |
   | status                    | ACTIVE                               |
   +---------------------------+--------------------------------------+

.. note::

   The output above assumes admin credentials but it is not necessary
   and member credentials will work to create the network as a tenant.

Port binding process
--------------------

When a baremetal port is bound to the EVPN VXLAN network:

#. **EVPN L2VNI driver processes the port**

   * Identifies that the port is a baremetal port (VNIC type is ``baremetal``)
   * Finds the VXLAN segment (VNI 10000)
   * Extracts the physical network name from the port's binding profile
     (provided by Ironic)

#. **Dynamic VLAN segment allocation or reuse**

   * Checks if a VLAN segment for the physical network already exists
   * If not, allocates a dynamic VLAN segment on the physical network using
     the network segment range
   * Multiple baremetal ports on the same physical network share the same
     VLAN segment

#. **Hierarchical binding**

   * Creates a binding level for the VXLAN segment
   * Passes the VLAN segment to the next mechanism driver (e.g.,
     networking-generic-switch)

#. **Switch configuration**

   The next mechanism driver configures the physical switch:

   * Assigns the VLAN to the switch port
   * The switch itself (via EVPN BGP configuration) maps the VLAN to the
     VXLAN VNI

Example configuration
~~~~~~~~~~~~~~~~~~~~~

Complete example with Ironic and networking-generic-switch
-----------------------------------------------------------

This example demonstrates a complete EVPN VXLAN setup with baremetal servers:

#. **Configure ML2 plugin** (``/etc/neutron/plugins/ml2/ml2_conf.ini``):

   .. code-block:: ini

      [ml2]
      type_drivers = vlan,vxlan
      mechanism_drivers = evpn-l2vni,networking-generic-switch
      tenant_network_types = vxlan

      [ml2_type_vlan]
      network_vlan_ranges = physnet1:100:200,physnet2:100:200

      [ml2_type_vxlan]
      vni_ranges = 10000:20000

#. **Configure networking-generic-switch**:

``/etc/neutron/plugins/ml2/ml2_conf_genericswitch.ini``

   .. code-block:: ini

      [genericswitch:tor-switch-1]
      device_type = netmiko_dell_os10
      ip = 192.0.2.10
      username = admin
      password = secret

      [genericswitch:tor-switch-2]
      device_type = netmiko_dell_os10
      ip = 192.0.2.11
      username = admin
      password = secret

#. **Configure EVPN on the ToR switches**

   Each ToR switch needs EVPN BGP configuration to participate in the VXLAN
   overlay. Example for Dell OS10:

   .. code-block:: text

      router bgp 65001
        neighbor 192.0.2.1 remote-as 65000
        !
        address-family l2vpn evpn
          neighbor 192.0.2.1 activate
        exit-address-family
      !
      evpn
        vni 10000
      !
      interface vlan 100
        description Baremetal VLAN for VNI 10000
        mode evpn
        vxlan vni 10000

#. **Register baremetal node in Ironic**

   When enrolling a baremetal node, provide the switch port information:

   .. code-block:: console

      $ openstack baremetal node create --driver redfish \
        --name baremetal-1

      $ openstack baremetal port create \
        --node baremetal-1 \
        --physical-network physnet1 \
        --local-link-connection switch_id=aa:bb:cc:dd:ee:01 \
        --local-link-connection port_id=Ethernet1/1/1 \
        --local-link-connection switch_info=tor-switch-1 \
        aa:bb:cc:dd:ee:ff

#. **Create network and subnet**

   .. note::

      A regular tenant is able to create a network which they
      can then supply to Nova using the nova-ironic driver to
      create a baremetal server on the network.

   .. code-block:: console

      $ openstack network create baremetal-net

      $ openstack subnet create --network baremetal-net \
        --subnet-range 192.168.100.0/24 --gateway 192.168.100.1 \
        --allocation-pool start=192.168.100.10,end=192.168.100.200 \
        baremetal-subnet

#. **Deploy instance on baremetal**

   .. code-block:: console

      $ openstack server create --flavor baremetal --image ubuntu-20.04 \
        --nic net-id=baremetal-net \
        my-baremetal-instance

   During deployment, Neutron will:

   * Bind the port to the VXLAN VNI 10000 segment
   * Create/reuse a dynamic VLAN segment (e.g., VLAN 100)
   * Configure the ToR switch port for VLAN 100
   * The switch maps VLAN 100 to VXLAN VNI 10000 via EVPN

Additional Improvements
~~~~~~~~~~~~~~~~~~~~~~~

Multiple fabric support
-----------------------

Today Neutron only supports one fabric / VXLAN overlay per instance of Neutron
but there exist configurations where multiple fabrics / VXLAN overlays for a
given deployment of OpenStack. For example a tenant fabric and a provider
fabric to provide cross connectivity or connectivity to network attached
storage or two different pools of Ironic nodes connected to separate fabrics.

The EVPN L2VNI driver could support a special syntax for specifying multiple
physical networks in scenarios where the EVPN network and VLAN segment
use different physical network names:

.. code-block:: text

   physical_network: "evpn-physnet:vlan-physnet"

The driver will:

* Use ``evpn-physnet`` for the VXLAN fabric
* Use ``vlan-physnet`` for the dynamically allocated VLAN segment

If a colon is not present, the ``evpn-physnet`` is considered empty or
``None``.

Or the Ironic Port / Portgroup ``category`` field could be used for the VXLAN
fabric.

An additional ``evpn-vxlan`` ML2 type could exist which would allow for
a ``physical_network`` to be supplied like VLAN today.

Trunk ports and subports
------------------------

The EVPN L2VNI driver supports Neutron trunk ports, allowing a single physical
server NIC to carry multiple networks using 802.1Q VLAN tagging.

To create a trunk port:

.. code-block:: console

   $ openstack network trunk create server-trunk --parent-port parent-port-id
   $ openstack network trunk set server-trunk \
     --subport port=subport-id,segmentation-type=vlan,segmentation-id=200

The ``segmentation-id`` in the trunk subport configuration represents the
tenant-visible VLAN tag. If VLAN translation is enabled on the switches, this
may differ from the switch-local VLAN ID.

Layer-3 Routing with SVIs
-------------------------

.. note::

   This functionality requires ML2 mechanism driver support for configuring
   SVIs on physical switches. Check with your switch vendor's driver
   documentation for availability.

Utilizing Switched Virtual Interfaces (SVIs) for layer-3 routing, modern
EVPN fabrics support **anycast gateway** functionality. This means:

* The same gateway IP address is configured on every ToR switch
* Servers use their local ToR switch as the gateway
* No need for traffic to traverse the fabric to reach a centralized router
* Improved performance and reduced latency for routed traffic

To configure SVIs in OpenStack, create a router with a flavor that your
ML2 mechanism supports for configuring an anycast gateway on your switch:

.. code-block:: console

   $ openstack router create --flavor svi my-svi-router
   $ openstack router add subnet my-svi-router baremetal-subnet

The switch configuration driver will create the SVI on all relevant ToR
switches with anycast gateway configuration.

Considerations
~~~~~~~~~~~~~~

* **VNIC type support**: The EVPN L2VNI mechanism driver only processes ports
  with VNIC type ``baremetal``. Virtual machine ports are not affected.

* **Dynamic segment cleanup**: When a baremetal port is unbound, the mechanism
  driver checks if the dynamic VLAN segment is still in use by other ports.
  If no other ports are using the segment, it is automatically released.

* **Switch capabilities**: The physical switches must support EVPN VXLAN
  capabilities, including:

  * VLAN-to-VNI mapping
  * BGP EVPN route distribution
  * VXLAN encapsulation/decapsulation (VTEP functionality)
  * Optionally: VLAN translation for trunk ports
  * Optionally: Anycast gateway for SVI routing

* **Network segmentation**: The VXLAN VNI range and VLAN range must be properly
  configured in the ML2 plugin to avoid conflicts.

* **Scale considerations**: While VXLAN VNIs support 16 million identifiers
  (24-bit VNI), physical VLAN IDs are limited to 4094 per physical network.
  With VLAN translation, this limit applies per physical network rather than
  fabric-wide.

* **Routing between EVPN networks**: Layer-3 routing between different EVPN
  VXLAN networks requires either physical routing infrastructure (SVIs with
  BGP), integration with projects like OVN with BGP capabilities, or use of
  OpenStack software routers.

* **Fabric architecture**: The fabric must be designed with proper spine-leaf
  topology and sufficient bandwidth to handle east-west traffic between
  cabinets. Consider VPC/MLAG configuration for ToR redundancy.

* **Additional OpenStack services support**: To provide connectivity to other
  systems like Nova based VMs, another ML2 mechanism like ``ovn`` needs to
  be loaded as well.

Limitations and Bugs
~~~~~~~~~~~~~~~~~~~~

* Inter-connectivity with Nova VMs and Ironic baremetal nodes does not work
  due to the way Neutron tracks the segment that a port is connected to via
  the IP address. Tracking via the IP address would only work with L3VNI but
  it is not possible to create a shared VRF between OVN and a baremetal
  switch at this time. `Bug 2114451 <https://bugs.launchpad.net/neutron/+bug/2114451>`_
  and `the subnet implementation <https://review.opendev.org/c/openstack/neutron/+/840418>`_.

* Multiple Fabrics / VXLAN overlays are not supported in one Neutron
  instance due to the lack of ``physical_network`` being allowed on the vxlan
  type driver. To solve this a new `evpn-vxlan type has been proposed
  <https://review.opendev.org/c/openstack/neutron-specs/+/952166>`_.

* Trunked VLAN details is not provided in configdrive/metadata by Nova.
  See `Expose vlan trunking in metadata/configdrive
  <https://review.opendev.org/c/openstack/nova-specs/+/471815>`_ and
  `Add trunk info to metadata/configdrive
  <https://review.opendev.org/c/openstack/nova/+/941227>`_ for a spec
  and implementation to extend Nova.


Related documentation
~~~~~~~~~~~~~~~~~~~~~

* :ref:`config-network-segment-ranges` - Network Segment Ranges necessary
  for the dynamic VLAN assignment
* :ref:`config-routed-provider-networks` - Similar concept for multi-segment
  layer-3 networks
* Ironic documentation: `Configuring Neutron networking
  <https://docs.openstack.org/ironic/latest/admin/dhcp-less.html>`_
* networking-generic-switch documentation for physical switch configuration
* OVN BGP Agent for interconnection between VXLAN overlays and external
  networks

References
~~~~~~~~~~

* `EVPN L2VNI Specification
  <https://review.opendev.org/c/openstack/neutron-specs/+/952166>`_
* `Ironic EVPN Support Specification
  <https://review.opendev.org/c/openstack/ironic-specs/+/959401>`_
* `Ports should reference the segment they are bound to
  <https://bugs.launchpad.net/neutron/+bug/2114451>`_
