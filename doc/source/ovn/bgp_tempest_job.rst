.. _bgp_tempest_job:

===================================
BGP Multinode Tempest Job
===================================

The ``neutron-ovn-bgp-tempest-multinode`` Zuul job is a CI job that validates
Neutron with Native OVN BGP in a realistic leaf-spine network topology. It
deploys a five-node environment where VXLAN tunnels simulate the physical links
of a leaf-spine fabric, and FRR (Free Range Routing) provides BGP and BFD on
every network node. The job then runs the Neutron Tempest scenario tests to
verify that tenant workloads are reachable through dynamically advertised BGP
routes.

The job is defined in ``zuul.d/tempest-multinode-bgp.yaml``.

Network Topology
================

The job provisions five nodes arranged in a leaf-spine topology.
Because CI nodes only have IP-level connectivity to each other, the playbook
``playbooks/configure_bgp_networking.yaml`` builds the fabric links on top of
VXLAN tunnels carried over the nodepool underlay.

::

                          +-----------------+
                          |      Spine      |
                          |   (AS 65000)    |
                          |   FRR / BGP     |
                          |  Tempest runner |
                          +--+----------+---+
                             |          |
                       VXLAN |          | VXLAN
                             |          |
                    +--------+-+      +-+--------+
                    |  Leaf-1  |      |  Leaf-2  |
                    |(AS 64999)|      |(AS 64999)|
                    |  FRR/BGP |      |  FRR/BGP |
                    +---+--+---+      +---+--+---+
                        |  |              |  |
                  VXLAN |  | VXLAN  VXLAN |  | VXLAN
                        |  |              |  |
    +-------------------+  |              |  +-------------------+
    |    Controller     |  |              |  |     Compute1      |
    |  OpenStack        |  |              |  |  OpenStack        |
    |  control + compute+--|--------------+  |  compute          |
    |  OVN agent        |  |                 |  OVN agent        |
    |  (ovn-bgp ext.)   |  +-----------------+  (ovn-bgp ext.)   |
    |  (br-bgp-0/1)     |                    |  (br-bgp-0/1)     |
    +-------------------+                    +-------------------+

Both the controller and compute1 are dual-homed: each connects to **both**
leaf-1 and leaf-2 through independent VXLAN tunnels (see the wiring table
below for details).

Every link in the diagram is a VXLAN tunnel terminated on an OVS bridge
(``br-infra``) at each end. VLAN tags on ``br-infra`` isolate the individual
point-to-point segments so that each BGP session runs over its own L2 domain.

Node Descriptions
=================

Controller
----------

The controller runs the full OpenStack control plane: Neutron (ML2/OVN),
Nova, Keystone, Glance, and supporting services. It also runs the
**OVN agent** (``q-ovn-agent`` service) with the ``ovn-bgp`` extension
enabled alongside the metadata extension.

Key characteristics:

* OVN is built from source (pinned commits for OVN and OVS) so that the
  latest BGP-related OVN features are available.
* TLS is enabled for all OpenStack services.
* Two OVS bridges, ``br-bgp-0`` and ``br-bgp-1``, are created as BGP peer
  bridges. The ``ovn-bgp`` extension programs OpenFlow rules on these bridges
  to steer traffic between the OVN datapath and the leaf switches.
* Each ``br-bgp-N`` bridge is connected to ``br-infra`` through a veth pair,
  with traffic isolated by VLAN tags on the ``br-infra`` side.
* Distributed floating IPs are enabled
  (``enable_distributed_floating_ip: True``).
* The gateway chassis is **not** assigned to the public bridge
  (``Q_ASSIGN_GATEWAY_TO_PUBLIC_BRIDGE: false``), since BGP handles
  external reachability instead of the traditional ``br-ex`` path.
* The OVN BGP agent (``q-ovn-bgp``) manages OpenFlow rules on the BGP
  bridges. FRR redistributes routes via BGP.

Compute1
--------

Compute1 runs as a second compute node. No OpenStack control plane services
run on this node, but Nova instances can be scheduled onto it. Like the
controller, it runs the **OVN agent** with the ``ovn-bgp`` and ``metadata``
extensions, and FRR with BFD for BGP route advertisement.

Key characteristics:

* OVN is built from source (same pinned commits as the controller).
* Two OVS bridges, ``br-bgp-0`` and ``br-bgp-1``, connect to the leaf
  switches through VXLAN tunnels on ``br-infra``, using the same veth-pair
  wiring as the controller.
* Distributed floating IPs are enabled
  (``enable_distributed_floating_ip: True``).
* The OVN BGP agent (``q-ovn-bgp``) manages OpenFlow rules on the BGP
  bridges. FRR redistributes routes via BGP.

Leaf-1 and Leaf-2
-----------------

The two leaf nodes act as Top-of-Rack (ToR) switches in the simulated
leaf-spine fabric. Each leaf has three BGP sessions:

* **Downlinks** (to the controller and compute1) -- iBGP within AS 64999.
  The leaf is configured as a route-reflector client toward both the
  controller and compute1, and originates a default route on each downlink.
* **Uplink** (to the spine) -- eBGP peering between AS 64999 (leaf) and
  AS 65000 (spine).

Key characteristics:

* FRR runs ``bgpd``, ``bfdd``, and ``zebra`` daemons.
* BFD is enabled on all BGP sessions for sub-second failure detection (500 ms
  intervals, detect multiplier 10).
* Graceful restart with forwarding-state preservation is enabled, so that
  during an OVN agent restart the data plane continues to forward traffic.
* Only host-prefix routes (``/32`` for IPv4, ``/128`` for IPv6) are accepted
  from the spine uplink, preventing the leaf from absorbing aggregate routes.
* Connected routes are redistributed into BGP, giving the spine visibility
  of the leaf's directly attached subnets.
* OVS is installed for the ``br-infra`` bridge that terminates VXLAN tunnels,
  but no OpenStack services run on these nodes.

Spine
-----

The spine node serves two roles: it is the **top of the routing fabric** and
the **Tempest test runner**.

As a network switch:

* FRR peers with both leafs over eBGP (AS 65000, leafs are external
  AS 64999).
* Connected routes are redistributed so the leafs learn the spine's
  loopback (``172.31.1.1/32``) and any other directly attached prefixes.
* Only host-prefix routes are accepted from the leafs, matching the
  per-VM ``/32`` and ``/128`` routes advertised via BGP.
* A route-map sets the source IP to ``172.31.1.1`` for IPv4 packets destined
  to host-only prefixes, ensuring return traffic uses a stable address.
* BFD is enabled on all downlink sessions.

As the Tempest runner:

* Tempest is installed and executed from this node so that test traffic
  originates from outside the OpenStack control plane, exercising the full
  BGP-advertised path to reach tenant workloads.
* Concurrency is set to 4.
* The test VM image is Ubuntu 22.04 minimal (cloud image), customised at
  boot.

VXLAN Tunnel Wiring
====================

The pre-run playbook creates the following tunnels:

.. list-table::
   :header-rows: 1

   * - Endpoints
     - VXLAN Key
     - VLAN Tag (br-infra)
     - BGP session carried
   * - Controller <-> Leaf-1
     - 10000
     - 1000
     - Controller (br-bgp-0) <-> Leaf-1 (controller-port)
   * - Controller <-> Leaf-2
     - 10001
     - 1001
     - Controller (br-bgp-1) <-> Leaf-2 (controller-port)
   * - Compute1 <-> Leaf-1
     - 10020
     - 3000
     - Compute1 (br-bgp-0) <-> Leaf-1 (compute1-port)
   * - Compute1 <-> Leaf-2
     - 10021
     - 3001
     - Compute1 (br-bgp-1) <-> Leaf-2 (compute1-port)
   * - Spine <-> Leaf-1
     - 10010
     - 2000
     - Spine (leaf0-port) <-> Leaf-1 (spine-port)
   * - Spine <-> Leaf-2
     - 10011
     - 2001
     - Spine (leaf1-port) <-> Leaf-2 (spine-port)

BGP Route Flow
==============

When the ``ovn-bgp`` extension on a compute node (the controller or compute1)
detects a new tenant VM or floating IP, the following sequence propagates the
route to the spine:

#. The ``ovn-bgp`` extension adds a ``/32`` (or ``/128``) route to the
   node's kernel routing table and programs OpenFlow rules on
   ``br-bgp-0`` and ``br-bgp-1``.
#. FRR on the node (via zebra) picks up the connected route and
   advertises it over the iBGP sessions to the leaf switches.
#. Each leaf, acting as a route-reflector, propagates the route over eBGP
   to the spine.
#. The spine installs the route into its FIB. Traffic from the Tempest runner
   on the spine can now reach the tenant VM by following the advertised path
   back through the leaf to the originating compute node.

Test Scope
==========

The job runs ``neutron_tempest_plugin.scenario`` tests and
``tempest.scenario.test_server_basic_ops.TestServerBasicOps``.

The following test areas are excluded because they exercise features not yet
supported with Neutron with Native OVN BGP:

* Port forwardings (``test_port_forwardings``)
* Multiple gateways (``test_multiple_gws``)
* SNAT to external IP (``test_snat_external_ip``)
* Default security group scenarios (``test_default_sec_grp_scenarios``)

The job runs in the **check** pipeline as a **non-voting** job.
