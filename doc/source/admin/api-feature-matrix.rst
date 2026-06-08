.. _api-feature-matrix:

======================================================
Comparison of Advanced Network Service APIs in Neutron
======================================================

This document provides a comparison of all advanced services (like firewall,
BGP, VPN etc.),
and other advanced networking APIs available in Neutron core and Neutron
stadium projects. It includes information on which backend (OVS or OVN)
supports each feature.

.. note::

   The OVN BGP service plugin (``ovn-bgp``) is **not** an API extension.
   It is an internal service plugin that prepares OVN logical topology and
   OpenFlow rules for BGP advertisement in spine-and-leaf fabrics.  An
   external routing suite (e.g. FRR) handles the actual BGP protocol.
   See :ref:`ovn_bgp` for details.

Neutron Core L3 APIs
--------------------

.. list-table::
   :header-rows: 1

   * - API Endpoint
     - Project
     - OVS
     - OVN
     - Description
   * - Routers (CRUD)
     - neutron
     - yes
     - yes
     - Logical routers for forwarding packets across internal subnets and NATting on external networks
   * - Router Extra Routes
     - neutron
     - yes
     - yes
     - Static routes (destination/nexthop pairs) via ``extraroute`` extension
   * - Router Extra Routes Atomic
     - neutron
     - yes
     - yes
     - Atomic add/remove of extra routes via ``add_extraroutes`` / ``remove_extraroutes`` actions
   * - Router DVR
     - neutron
     - yes
     - \-
     - Distributed Virtual Router -- distributes routing across compute nodes (Note: OVN supports distributed Floating IPs)
   * - Router HA (``l3-ha``)
     - neutron
     - yes
     - \-
     - VRRP-based high availability for routers
   * - Router External Gateway Multihoming
     - neutron
     - \-
     - yes
     - Multiple external gateway ports with ECMP/BFD policy for default routes
   * - Router Default Route ECMP (``enable-default-route-ecmp``)
     - neutron
     - \-
     - yes
     - Enable/disable ECMP default routes based on gateway subnet defaults
   * - Router Default Route BFD (``enable-default-route-bfd``)
     - neutron
     - \-
     - yes
     - Enable/disable BFD monitoring for router default routes
   * - Router NDP Proxy
     - neutron
     - yes
     - yes
     - Announce unique IPv6 address to external network via NDP proxy
   * - Router Conntrack Helpers
     - neutron
     - \-
     - yes
     - Configure netfilter CT target rules on routers
   * - Router L3 Agent Scheduler
     - neutron
     - yes
     - yes
     - Schedule routers to L3 agents (possible with OVN since https://bugs.launchpad.net/neutron/+bug/2103521)
   * - Floating IPs (CRUD)
     - neutron
     - yes
     - yes
     - NAT between external and internal networks
   * - Floating IP Port Forwarding
     - neutron
     - yes
     - yes
     - DNAT rules mapping external port to internal port/IP on a floating IP
   * - Floating IP Pools
     - neutron
     - yes
     - yes
     - List available floating IP pools
   * - Subnets (CRUD)
     - neutron
     - yes
     - yes
     - Create and manage subnets within networks
   * - Subnet Onboard
     - neutron
     - yes
     - yes
     - Onboard existing subnets into subnet pools
   * - Subnet Pools (CRUD)
     - neutron
     - yes
     - yes
     - Manage pools of subnet CIDR allocations
   * - Subnet Pool Prefix Operations
     - neutron
     - yes
     - yes
     - Add/remove prefixes from subnet pools
   * - Address Scopes
     - neutron
     - yes
     - yes
     - Group subnet pools for routing policy
   * - Local IPs
     - neutron
     - yes
     - \-
     - Virtual anycast IP reachable only within the same physical node
   * - Metering Labels and Rules
     - neutron
     - yes
     - \-
     - L3 metering labels and rules for traffic accounting on routers
   * - Logging
     - neutron
     - yes
     - yes
     - Security and Firewall group logging for auditing accepted/dropped packets

OVN BGP Service Plugin (non-API)
---------------------------------

.. list-table::
   :header-rows: 1

   * - Feature
     - Project
     - OVS
     - OVN
     - Description
   * - OVN BGP Service Plugin + Agent Extension
     - neutron (``ovn-bgp``)
     - \-
     - yes
     - Prepares OVN logical topology and OpenFlow rules for BGP advertisement
       in spine-and-leaf fabrics. Requires external FRR for actual BGP protocol.
       Not exposed as an API extension. See :ref:`ovn_bgp`.

BGP Dynamic Routing
-------------------

.. list-table::
   :header-rows: 1

   * - API Endpoint
     - Project
     - OVS
     - OVN
     - Description
   * - BGP Speakers
     - neutron-dynamic-routing
     - yes
     - yes
     - Route server using BGP to advertise routes to peers
   * - BGP Peers
     - neutron-dynamic-routing
     - yes
     - yes
     - Define BGP infrastructure (routers, route reflectors) for peering
   * - BGP DR Agent Scheduler
     - neutron-dynamic-routing
     - yes
     - yes
     - Schedule BGP Speakers to Dynamic Routing Agents

BGP/MPLS VPN Interconnection
-----------------------------

.. list-table::
   :header-rows: 1

   * - API Endpoint
     - Project
     - OVS
     - OVN
     - Description
   * - BGPVPN (CRUD)
     - networking-bgpvpn
     - yes
     - \-
     - Associate networks/routers with MPLS VPNs via BGP using Route Targets
   * - BGPVPN Network Associations
     - networking-bgpvpn
     - yes
     - \-
     - Associate BGPVPNs with Neutron networks
   * - BGPVPN Router Associations
     - networking-bgpvpn
     - yes
     - \-
     - Associate BGPVPNs with Neutron routers
   * - BGPVPN Port Associations
     - networking-bgpvpn
     - yes
     - \-
     - Associate BGPVPNs with Neutron ports (``bgpvpn-routes-control``)

VPNaaS
------

.. list-table::
   :header-rows: 1

   * - API Endpoint
     - Project
     - OVS
     - OVN
     - Description
   * - VPN Services
     - neutron-vpnaas
     - yes
     - yes
     - Site-to-site VPN service associated with router and subnet
   * - IKE Policies
     - neutron-vpnaas
     - yes
     - yes
     - IKEv1/v2 key exchange policies (3des, aes-128/192/256)
   * - IPsec Policies
     - neutron-vpnaas
     - yes
     - yes
     - IPsec encryption, auth, transform protocol, encapsulation mode
   * - IPsec Site Connections
     - neutron-vpnaas
     - yes
     - yes
     - IPsec site-to-site connections with Dead Peer Detection
   * - Endpoint Groups
     - neutron-vpnaas
     - yes
     - yes
     - Group subnets/CIDRs as local or peer endpoints for VPN

FWaaS v2
--------

.. list-table::
   :header-rows: 1

   * - API Endpoint
     - Project
     - OVS
     - OVN
     - Description
   * - Firewall Groups
     - neutron-fwaas
     - yes
     - yes
     - Logical firewall with ingress/egress policies applied to ports
   * - Firewall Policies
     - neutron-fwaas
     - yes
     - yes
     - Ordered collection of firewall rules (shareable across projects)
   * - Firewall Rules
     - neutron-fwaas
     - yes
     - yes
     - TCP/UDP/ICMP or protocol-agnostic traffic filtering rules

Service Function Chaining
--------------------------

.. list-table::
   :header-rows: 1

   * - API Endpoint
     - Project
     - OVS
     - OVN
     - Description
   * - Port Chains
     - networking-sfc
     - yes
     - \-
     - Ordered list of port pair groups for traffic steering
   * - Port Pair Groups
     - networking-sfc
     - yes
     - \-
     - Groups of port pairs for load balancing within a service function
   * - Port Pairs
     - networking-sfc
     - yes
     - \-
     - Ingress/egress port pairs representing a service function instance
   * - Flow Classifiers
     - networking-sfc
     - yes
     - \-
     - Classify traffic flows for steering into port chains
   * - Service Graphs
     - networking-sfc
     - yes
     - \-
     - Directed graphs of port chains for complex topologies

Tap as a Service
----------------

.. list-table::
   :header-rows: 1

   * - API Endpoint
     - Project
     - OVS
     - OVN
     - Description
   * - Tap Services
     - tap-as-a-service
     - yes
     - \-
     - Define destination port for mirrored traffic analysis
   * - Tap Flows
     - tap-as-a-service
     - yes
     - \-
     - Define source ports/traffic to mirror to a tap service
   * - Tap Mirrors
     - tap-as-a-service
     - yes
     - yes
     - Mirror traffic to external IP via GRE or ERSPAN v1 tunnel
