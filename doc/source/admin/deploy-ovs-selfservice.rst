.. _deploy-ovs-selfservice:

===================================
Open vSwitch: Self-service networks
===================================

This architecture example augments :ref:`deploy-ovs-provider` to support
a nearly limitless quantity of entirely virtual networks. Although the
Networking service supports VLAN self-service networks, this example
focuses on VXLAN self-service networks. For more information on
self-service networks, see :ref:`intro-os-networking-selfservice`.

Prerequisites
~~~~~~~~~~~~~

Add one network node with the following components:

* Three network interfaces: management, provider, and overlay.
* OpenStack Networking Open vSwitch (OVS) layer-2 agent, layer-3 agent, and
  any including OVS.

Modify the compute nodes with the following components:

* Add one network interface: overlay.

.. note::

   You can keep the DHCP and metadata agents on each compute node or
   move them to the network node.

Architecture
~~~~~~~~~~~~

.. image:: figures/deploy-ovs-selfservice-overview.png
   :alt: Self-service networks using OVS - overview

The following figure shows components and connectivity for one self-service
network and one untagged (flat) provider network. In this particular case, the
instance resides on the same compute node as the DHCP agent for the network.
If the DHCP agent resides on another compute node, the latter only contains
a DHCP namespace and with a port on the OVS integration bridge.

.. image:: figures/deploy-ovs-selfservice-compconn1.png
   :alt: Self-service networks using OVS - components and connectivity - one network

Example configuration
~~~~~~~~~~~~~~~~~~~~~

Use the following example configuration as a template to add support for
self-service networks to an existing operational environment that supports
provider networks.

Controller node
---------------

#. In the ``neutron.conf`` file:

   * Enable routing and allow overlapping IP address ranges.

     .. code-block:: ini

        [DEFAULT]
        service_plugins = router
        allow_overlapping_ips = True

#. In the ``ml2_conf.ini`` file:

   * Add ``vxlan`` to type drivers and project network types.

     .. code-block:: ini

        [ml2]
        type_drivers = flat,vlan,vxlan
        tenant_network_types = vxlan

   * Enable the layer-2 population mechanism driver.

     .. code-block:: ini

        [ml2]
        mechanism_drivers = openvswitch,l2population

   * Configure the VXLAN network ID (VNI) range.

     .. code-block:: ini

        [ml2_type_vxlan]
        vni_ranges = VNI_START:VNI_END

     Replace ``VNI_START`` and ``VNI_END`` with appropriate numerical
     values.

#. Restart the following services:

   * Neutron Server
   * Open vSwitch agent

Network node
------------

#. Install the Networking service OVS layer-2 agent and layer-3 agent.

#. Install OVS.

#. In the ``neutron.conf`` file, configure common options:

   .. include:: shared/deploy-config-neutron-common.txt

#. Start the following services:

   * OVS

#. Create the OVS provider bridge ``br-provider``:

   .. code-block:: console

      $ ovs-vsctl add-br br-provider

#. Add the provider network interface as a port on the OVS provider
   bridge ``br-provider``:

   .. code-block:: console

      $ ovs-vsctl add-port br-provider PROVIDER_INTERFACE

   Replace ``PROVIDER_INTERFACE`` with the name of the underlying interface
   that handles provider networks. For example, ``eth1``.

#. In the ``openvswitch_agent.ini`` file, configure the layer-2 agent.

   .. code-block:: ini

      [ovs]
      bridge_mappings = provider:br-provider
      local_ip = OVERLAY_INTERFACE_IP_ADDRESS

      [agent]
      tunnel_types = vxlan
      l2_population = True

      [securitygroup]
      firewall_driver = iptables_hybrid

   Replace ``OVERLAY_INTERFACE_IP_ADDRESS`` with the IP address of the
   interface that handles VXLAN overlays for self-service networks.

#. In the ``l3_agent.ini`` file, configure the layer-3 agent.

   .. code-block:: ini

      [DEFAULT]
      interface_driver = openvswitch

#. Start the following services:

   * Open vSwitch agent
   * Layer-3 agent

Compute nodes
-------------

#. In the ``openvswitch_agent.ini`` file, enable VXLAN support including
   layer-2 population.

   .. code-block:: ini

      [ovs]
      local_ip = OVERLAY_INTERFACE_IP_ADDRESS

      [agent]
      tunnel_types = vxlan
      l2_population = True

   Replace ``OVERLAY_INTERFACE_IP_ADDRESS`` with the IP address of the
   interface that handles VXLAN overlays for self-service networks.

#. Restart the following services:

   * Open vSwitch agent

Verify service operation
------------------------

#. Source the administrative project credentials.
#. Verify presence and operation of the agents.

   .. code-block:: console

      $ openstack network agent list
      +--------------------------------------+--------------------+----------+-------------------+-------+-------+---------------------------+
      | ID                                   | Agent Type         | Host     | Availability Zone | Alive | State | Binary                    |
      +--------------------------------------+--------------------+----------+-------------------+-------+-------+---------------------------+
      | 1236bbcb-e0ba-48a9-80fc-81202ca4fa51 | Metadata agent     | compute2 | None              | True  | UP    | neutron-metadata-agent    |
      | 457d6898-b373-4bb3-b41f-59345dcfb5c5 | Open vSwitch agent | compute2 | None              | True  | UP    | neutron-openvswitch-agent |
      | 71f15e84-bc47-4c2a-b9fb-317840b2d753 | DHCP agent         | compute2 | nova              | True  | UP    | neutron-dhcp-agent        |
      | 8805b962-de95-4e40-bdc2-7a0add7521e8 | L3 agent           | network1 | nova              | True  | UP    | neutron-l3-agent          |
      | a33cac5a-0266-48f6-9cac-4cef4f8b0358 | Open vSwitch agent | network1 | None              | True  | UP    | neutron-openvswitch-agent |
      | a6c69690-e7f7-4e56-9831-1282753e5007 | Metadata agent     | compute1 | None              | True  | UP    | neutron-metadata-agent    |
      | af11f22f-a9f4-404f-9fd8-cd7ad55c0f68 | DHCP agent         | compute1 | nova              | True  | UP    | neutron-dhcp-agent        |
      | bcfc977b-ec0e-4ba9-be62-9489b4b0e6f1 | Open vSwitch agent | compute1 | None              | True  | UP    | neutron-openvswitch-agent |
      +--------------------------------------+--------------------+----------+-------------------+-------+-------+---------------------------+

Create initial networks
-----------------------

.. include:: shared/deploy-selfservice-initialnetworks.txt

Verify network operation
------------------------

.. include:: shared/deploy-selfservice-verifynetworkoperation.txt

.. _deploy-ovs-selfservice-networktrafficflow:

Network traffic flow
~~~~~~~~~~~~~~~~~~~~

.. include:: shared/deploy-selfservice-networktrafficflow.txt

.. _deploy-ovs-selfservice-networktrafficflow-ns1:

North-south scenario 1: Instance with a fixed IP address
--------------------------------------------------------

For instances with a fixed IPv4 address, the network node performs SNAT
on north-south traffic passing from self-service to external networks
such as the Internet. For instances with a fixed IPv6 address, the network
node performs conventional routing of traffic between self-service and
external networks.

* The instance resides on compute node 1 and uses self-service network 1.
* The instance sends a packet to a host on the Internet.

The following steps involve compute node 1:

#. The instance interface (1) forwards the packet to the security group
   bridge instance port (2) via ``veth`` pair.
#. Security group rules (3) on the security group bridge handle firewalling
   and connection tracking for the packet.
#. The security group bridge OVS port (4) forwards the packet to the OVS
   integration bridge security group port (5) via ``veth`` pair.
#. The OVS integration bridge adds an internal VLAN tag to the packet.
#. The OVS integration bridge exchanges the internal VLAN tag for an internal
   tunnel ID.
#. The OVS integration bridge patch port (6) forwards the packet to the
   OVS tunnel bridge patch port (7).
#. The OVS tunnel bridge (8) wraps the packet using VNI 101.
#. The underlying physical interface (9) for overlay networks forwards
   the packet to the network node via the overlay network (10).

The following steps involve the network node:

#. The underlying physical interface (11) for overlay networks forwards
   the packet to the OVS tunnel bridge (12).
#. The OVS tunnel bridge unwraps the packet and adds an internal tunnel ID
   to it.
#. The OVS tunnel bridge exchanges the internal tunnel ID for an internal
   VLAN tag.
#. The OVS tunnel bridge patch port (13) forwards the packet to the OVS
   integration bridge patch port (14).
#. The OVS integration bridge port for the self-service network (15)
   removes the internal VLAN tag and forwards the packet to the self-service
   network interface (16) in the router namespace.

   * For IPv4, the router performs SNAT on the packet which changes the
     source IP address to the router IP address on the provider network
     and sends it to the gateway IP address on the provider network via
     the gateway interface on the provider network (17).
   * For IPv6, the router sends the packet to the next-hop IP address,
     typically the gateway IP address on the provider network, via the
     provider gateway interface (17).

#. The router forwards the packet to the OVS integration bridge port for
   the provider network (18).
#. The OVS integration bridge adds the internal VLAN tag to the packet.
#. The OVS integration bridge ``int-br-provider`` patch port (19) forwards
   the packet to the OVS provider bridge ``phy-br-provider`` patch port (20).
#. The OVS provider bridge swaps the internal VLAN tag with actual VLAN tag
   101.
#. The OVS provider bridge provider network port (21) forwards the packet to
   the physical network interface (22).
#. The physical network interface forwards the packet to the Internet via
   physical network infrastructure (23).

.. note::

   Return traffic follows similar steps in reverse. However, without a
   floating IPv4 address, hosts on the provider or external networks cannot
   originate connections to instances on the self-service network.

.. image:: figures/deploy-ovs-selfservice-flowns1.png
   :alt: Self-service networks using Open vSwitch - network traffic flow - north/south scenario 1

North-south scenario 2: Instance with a floating IPv4 address
-------------------------------------------------------------

For instances with a floating IPv4 address, the network node performs SNAT
on north-south traffic passing from the instance to external networks
such as the Internet and DNAT on north-south traffic passing from external
networks to the instance. Floating IP addresses and NAT do not apply to IPv6.
Thus, the network node routes IPv6 traffic in this scenario.

* The instance resides on compute node 1 and uses self-service network 1.
* A host on the Internet sends a packet to the instance.

The following steps involve the network node:

#. The physical network infrastructure (1) forwards the packet to the
   provider physical network interface (2).
#. The provider physical network interface forwards the packet to the
   OVS provider bridge provider network port (3).
#. The OVS provider bridge swaps actual VLAN tag 101 with the internal
   VLAN tag.
#. The OVS provider bridge ``phy-br-provider`` port (4) forwards the
   packet to the OVS integration bridge ``int-br-provider`` port (5).
#. The OVS integration bridge port for the provider network (6) removes
   the internal VLAN tag and forwards the packet to the provider network
   interface (6) in the router namespace.

   * For IPv4, the router performs DNAT on the packet which changes the
     destination IP address to the instance IP address on the self-service
     network and sends it to the gateway IP address on the self-service
     network via the self-service interface (7).
   * For IPv6, the router sends the packet to the next-hop IP address,
     typically the gateway IP address on the self-service network, via
     the self-service interface (8).

#. The router forwards the packet to the OVS integration bridge port for
   the self-service network (9).
#. The OVS integration bridge adds an internal VLAN tag to the packet.
#. The OVS integration bridge exchanges the internal VLAN tag for an internal
   tunnel ID.
#. The OVS integration bridge ``patch-tun`` patch port (10) forwards the
   packet to the OVS tunnel bridge ``patch-int`` patch port (11).
#. The OVS tunnel bridge (12) wraps the packet using VNI 101.
#. The underlying physical interface (13) for overlay networks forwards
   the packet to the network node via the overlay network (14).

The following steps involve the compute node:

#. The underlying physical interface (15) for overlay networks forwards
   the packet to the OVS tunnel bridge (16).
#. The OVS tunnel bridge unwraps the packet and adds an internal tunnel ID
   to it.
#. The OVS tunnel bridge exchanges the internal tunnel ID for an internal
   VLAN tag.
#. The OVS tunnel bridge ``patch-int`` patch port (17) forwards the packet
   to the OVS integration bridge ``patch-tun`` patch port (18).
#. The OVS integration bridge removes the internal VLAN tag from the packet.
#. The OVS integration bridge security group port (19) forwards the packet
   to the security group bridge OVS port (20) via ``veth`` pair.
#. Security group rules (21) on the security group bridge handle firewalling
   and connection tracking for the packet.
#. The security group bridge instance port (22) forwards the packet to the
   instance interface (23) via ``veth`` pair.

.. image:: figures/deploy-ovs-selfservice-flowns2.png
   :alt: Self-service networks using Open vSwitch - network traffic flow - north/south scenario 2

.. note::

   Egress instance traffic flows similar to north-south scenario 1, except SNAT
   changes the source IP address of the packet to the floating IPv4 address
   rather than the router IP address on the provider network.

East-west scenario 1: Instances on the same network
---------------------------------------------------

Instances with a fixed IPv4/IPv6 address or floating IPv4 address on the
same network communicate directly between compute nodes containing those
instances.

By default, the VXLAN protocol lacks knowledge of target location
and uses multicast to discover it. After discovery, it stores the
location in the local forwarding database. In large deployments,
the discovery process can generate a significant amount of network
that all nodes must process. To eliminate the latter and generally
increase efficiency, the Networking service includes the layer-2
population mechanism driver that automatically populates the
forwarding database for VXLAN interfaces. The example configuration
enables this driver. For more information, see :ref:`config-plugin-ml2`.

* Instance 1 resides on compute node 1 and uses self-service network 1.
* Instance 2 resides on compute node 2 and uses self-service network 1.
* Instance 1 sends a packet to instance 2.

The following steps involve compute node 1:

#. The instance 1 interface (1) forwards the packet to the security group
   bridge instance port (2) via ``veth`` pair.
#. Security group rules (3) on the security group bridge handle firewalling
   and connection tracking for the packet.
#. The security group bridge OVS port (4) forwards the packet to the OVS
   integration bridge security group port (5) via ``veth`` pair.
#. The OVS integration bridge adds an internal VLAN tag to the packet.
#. The OVS integration bridge exchanges the internal VLAN tag for an internal
   tunnel ID.
#. The OVS integration bridge patch port (6) forwards the packet to the
   OVS tunnel bridge patch port (7).
#. The OVS tunnel bridge (8) wraps the packet using VNI 101.
#. The underlying physical interface (9) for overlay networks forwards
   the packet to compute node 2 via the overlay network (10).

The following steps involve compute node 2:

#. The underlying physical interface (11) for overlay networks forwards
   the packet to the OVS tunnel bridge (12).
#. The OVS tunnel bridge unwraps the packet and adds an internal tunnel ID
   to it.
#. The OVS tunnel bridge exchanges the internal tunnel ID for an internal
   VLAN tag.
#. The OVS tunnel bridge ``patch-int`` patch port (13) forwards the packet
   to the OVS integration bridge ``patch-tun`` patch port (14).
#. The OVS integration bridge removes the internal VLAN tag from the packet.
#. The OVS integration bridge security group port (15) forwards the packet
   to the security group bridge OVS port (16) via ``veth`` pair.
#. Security group rules (17) on the security group bridge handle firewalling
   and connection tracking for the packet.
#. The security group bridge instance port (18) forwards the packet to the
   instance 2 interface (19) via ``veth`` pair.

.. image:: figures/deploy-ovs-selfservice-flowew1.png
   :alt: Self-service networks using Open vSwitch - network traffic flow - east/west scenario 1

.. note::

   Return traffic follows similar steps in reverse.

East-west scenario 2: Instances on different networks
-----------------------------------------------------

Instances using a fixed IPv4/IPv6 address or floating IPv4 address communicate
via router on the network node. The self-service networks must reside on the
same router.

* Instance 1 resides on compute node 1 and uses self-service network 1.
* Instance 2 resides on compute node 1 and uses self-service network 2.
* Instance 1 sends a packet to instance 2.

.. note::

   Both instances reside on the same compute node to illustrate how VXLAN
   enables multiple overlays to use the same layer-3 network.

The following steps involve the compute node:

#. The instance interface (1) forwards the packet to the security group
   bridge instance port (2) via ``veth`` pair.
#. Security group rules (3) on the security group bridge handle firewalling
   and connection tracking for the packet.
#. The security group bridge OVS port (4) forwards the packet to the OVS
   integration bridge security group port (5) via ``veth`` pair.
#. The OVS integration bridge adds an internal VLAN tag to the packet.
#. The OVS integration bridge exchanges the internal VLAN tag for an internal
   tunnel ID.
#. The OVS integration bridge ``patch-tun`` patch port (6) forwards the
   packet to the OVS tunnel bridge ``patch-int`` patch port (7).
#. The OVS tunnel bridge (8) wraps the packet using VNI 101.
#. The underlying physical interface (9) for overlay networks forwards
   the packet to the network node via the overlay network (10).

The following steps involve the network node:

#. The underlying physical interface (11) for overlay networks forwards
   the packet to the OVS tunnel bridge (12).
#. The OVS tunnel bridge unwraps the packet and adds an internal tunnel ID
   to it.
#. The OVS tunnel bridge exchanges the internal tunnel ID for an internal
   VLAN tag.
#. The OVS tunnel bridge ``patch-int`` patch port (13) forwards the packet to
   the OVS integration bridge ``patch-tun`` patch port (14).
#. The OVS integration bridge port for self-service network 1 (15)
   removes the internal VLAN tag and forwards the packet to the self-service
   network 1 interface (16) in the router namespace.
#. The router sends the packet to the next-hop IP address, typically the
   gateway IP address on self-service network 2, via the self-service
   network 2 interface (17).
#. The router forwards the packet to the OVS integration bridge port for
   self-service network 2 (18).
#. The OVS integration bridge adds the internal VLAN tag to the packet.
#. The OVS integration bridge exchanges the internal VLAN tag for an internal
   tunnel ID.
#. The OVS integration bridge ``patch-tun`` patch port (19) forwards the
   packet to the OVS tunnel bridge ``patch-int`` patch port (20).
#. The OVS tunnel bridge (21) wraps the packet using VNI 102.
#. The underlying physical interface (22) for overlay networks forwards
   the packet to the compute node via the overlay network (23).

The following steps involve the compute node:

#. The underlying physical interface (24) for overlay networks forwards
   the packet to the OVS tunnel bridge (25).
#. The OVS tunnel bridge unwraps the packet and adds an internal tunnel
   ID to it.
#. The OVS tunnel bridge exchanges the internal tunnel ID for an internal
   VLAN tag.
#. The OVS tunnel bridge ``patch-int`` patch port (26) forwards the packet
   to the OVS integration bridge ``patch-tun`` patch port (27).
#. The OVS integration bridge removes the internal VLAN tag from the packet.
#. The OVS integration bridge security group port (28) forwards the packet
   to the security group bridge OVS port (29) via ``veth`` pair.
#. Security group rules (30) on the security group bridge handle firewalling
   and connection tracking for the packet.
#. The security group bridge instance port (31) forwards the packet to the
   instance interface (32) via ``veth`` pair.

.. note::

   Return traffic follows similar steps in reverse.

.. image:: figures/deploy-ovs-selfservice-flowew2.png
   :alt: Self-service networks using Open vSwitch - network traffic flow - east/west scenario 2
