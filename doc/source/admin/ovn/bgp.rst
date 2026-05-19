.. _ovn_bgp:

===
BGP
===

.. note::

   This page documents the **OVN BGP service plugin** built into Neutron.
   This is distinct from the legacy
   :ref:`neutron-dynamic-routing BGP speaker <config-bgp-dynamic-routing>`,
   which is an external project with its own agent.

The OVN BGP service plugin integrates BGP route advertisements directly into
the Neutron server and the OVN Neutron Agent.  It is designed for
**spine-and-leaf** data-centre fabrics where every rack (leaf) is an
independent L3 routing domain and inter-rack traffic is forwarded over BGP
rather than stretched L2 VLANs.

Architecture overview
---------------------

A spine-and-leaf fabric consists of:

* **Leaf switches** -- top-of-rack (ToR) switches, each providing L2
  connectivity inside a single rack.
* **Spine switches** -- interconnecting all leaf switches via routed (L3)
  links.

Because every link between a leaf and the spine is a routed link, there is no
end-to-end L2 domain across racks.  BGP runs on every leaf (and optionally on
every compute node) to exchange reachability information.

::

           ┌────────┐       ┌────────┐
           │ Spine1 │       │ Spine2 │
           └───┬┬───┘       └───┬┬───┘
         ┌─────┘└─────┬─────────┘└─────┐
         │  BGP       │  BGP           │  BGP
    ┌────┴───┐   ┌────┴───┐      ┌─────┴──┐
    │ Leaf 1 │   │ Leaf 2 │      │ Leaf N │
    └──┬──┬──┘   └──┬──┬──┘      └──┬──┬──┘
       │  │         │  │            │  │
     ┌─┘  └─┐     ┌─┘  └─┐        ┌─┘  └─┐
     CN1  CN2     CN3  CN4        CN..  CN..

Each compute node (CN) has a point-to-point L2 link to its leaf switch port.
On the Neutron server side, a **flat** provider network is connected to a BGP
logical router topology that the plugin creates in the OVN Northbound
database.  On each chassis, a **BGP peer bridge** (an OVS bridge carrying
both a physical NIC port and a patch port to ``br-int``) bridges the OVN
overlay out to that per-NIC L2 link facing the leaf switch.  This way the
relevant IP prefixes (router gateway IPs, floating IPs) are advertised to the
leaf so that return traffic from the spine can be routed back to the correct
host.

Components
~~~~~~~~~~

The feature has two components:

**BGP service plugin** (``ovn-bgp``) -- runs inside the Neutron server
process.  It watches network creation events and manages the BGP topology in
the OVN Northbound database (logical routers, route policies, VRFs).

**BGP agent extension** (``ovn-bgp``) -- runs inside the OVN Neutron Agent on
every compute/network node.  It programs OpenFlow rules on the provider bridge
so that traffic arriving from the leaf switch is correctly steered to the OVN
integration bridge, and vice-versa.

.. important::

   Neither the BGP service plugin nor the BGP agent extension speaks the BGP
   protocol itself.  They only prepare the OVN logical topology and the
   OpenFlow data-path.  An external routing suite such as
   `FRR <https://frrouting.org/>`_ must be deployed on every node where BGP
   route advertisement is required (typically every compute and network node).
   FRR peers with the leaf switch and advertises the routes that OVN makes
   available through its VRF-based logical routers.


Why VLAN provider networks are not supported
--------------------------------------------

When the BGP service plugin is enabled it **rejects creation of VLAN provider
networks** with an HTTP 400 error:

.. warning::

   VLAN provider networks are not supported when the BGP service plugin
   is enabled. Only flat provider networks are supported.

The reason is architectural.  In a spine-and-leaf fabric:

1. **L2 does not cross rack boundaries.** Each leaf switch terminates L2 at
   the rack level.  A VLAN-tagged frame leaving one leaf cannot reach a
   different leaf through the spine because the spine routes at L3.

2. **VLAN tags are a local concern.** The leaf switch strips/adds VLAN tags
   locally; they have no meaning beyond the rack.  A Neutron VLAN provider
   network implies that a given VLAN ID carries the same broadcast domain
   across all hosts -- an assumption that breaks in a routed fabric.

3. **Flat networks model the local segment correctly.** A flat provider
   network does not assume any global L2 scope.  Combined with BGP route
   advertisement the reachability of IPs behind different racks is handled
   entirely at L3, which matches the physical topology.

.. note::

   If your deployment requires VLAN segmentation within a single rack (e.g.
   for separating management traffic from tenant traffic on the same physical
   NIC), that segmentation is handled at the OVS / OS level on the host and
   does not need a Neutron VLAN provider network.

   The existing documentation for
   :ref:`BGP floating IPs over L2 segmented networks
   <config-bgp-floating-ip-over-l2-segmented-network>` describes a different
   approach that uses the legacy ``neutron-dynamic-routing`` project and VLAN
   segments confined to individual racks.  That setup is unrelated to the OVN
   BGP plugin.


Enabling the plugin
-------------------

Server side
~~~~~~~~~~~

Add ``ovn-bgp`` to the list of service plugins in ``neutron.conf``:

.. code-block:: ini

   [DEFAULT]
   service_plugins = ovn-router,ovn-bgp

The plugin registers the following configuration options under the ``[bgp]``
section:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Option
     - Default
     - Description
   * - ``main_router_name``
     - ``bgp-lr-main``
     - Name of the main BGP logical router created in OVN.
   * - ``main_router_vrf_id``
     - ``42``
     - VRF ID attached to the main BGP logical router.
   * - ``chassis_router_vrf_id``
     - ``10``
     - VRF ID for per-chassis BGP routers.  Used to learn default routes for
       egress traffic leaving the chassis.

Agent side
~~~~~~~~~~

On every compute or network node, enable the ``ovn-bgp`` agent extension in
the OVN agent configuration file (e.g.
``/etc/neutron/plugins/ml2/ovn_agent.ini``):

.. code-block:: ini

   [agent]
   extensions = ovn-bgp

The agent extension watches OVS and OVN Southbound events to:

* Detect provider bridge creation and configure OpenFlow rules that steer
  ingress traffic from the physical NIC to the OVN integration bridge (via
  the patch port), and allow egress traffic out.
* Track the logical router port (LRP) MAC address bound to the local chassis
  so that incoming packets are rewritten with the correct destination MAC
  before entering OVN's pipeline.
* Advertise the set of BGP bridges to the OVN Southbound ``Chassis`` table so
  that the server-side reconciler can create the appropriate per-chassis
  logical routers and route policies.


Creating provider networks
--------------------------

With the BGP plugin active, provider networks must use the **flat** type:

.. code-block:: console

   $ openstack network create --external \
       --provider-physical-network physnet1 \
       --provider-network-type flat \
       provider

Attempting to create a VLAN provider network will fail:

.. code-block:: console

   $ openstack network create --external \
       --provider-physical-network physnet1 \
       --provider-network-type vlan \
       --provider-segment 100 \
       provider-vlan
   BadRequestException: 400: ...VLAN provider networks are not supported...

Overlay (Geneve, VXLAN, GRE) self-service networks remain fully supported and
are unaffected by the BGP plugin.
