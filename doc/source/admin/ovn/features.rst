.. _features:

Features
========

Open Virtual Network (OVN) offers the following virtual network
services:

* Layer-2 (switching)

  Native implementation. Replaces the conventional Open vSwitch (OVS)
  agent.

* Layer-3 (routing)

  Native implementation that supports distributed routing.  Replaces the
  conventional Neutron L3 agent. This includes transparent L3HA :doc:`routing`
  support, based on BFD monitorization integrated in core OVN.

* DHCP

  Native distributed implementation.  Replaces the conventional Neutron DHCP
  agent.  DNS is handled separately via OVN's built-in DNS table (see the
  DNS section below).

* DPDK

  OVN and the OVN mechanism driver may be used with OVS using either the Linux
  kernel datapath or the DPDK datapath.

* Trunk driver

  Uses OVN's functionality of parent port and port tagging to support trunk
  service plugin. One has to enable the 'trunk' service plugin in neutron
  configuration files to use this feature.

* VLAN project networks

  The OVN driver does support VLAN project networks when used
  with OVN version 2.11 (or higher).

* VLAN transparent networks

  The OVN driver supports VLAN transparent networks, allowing tenant
  traffic to carry VLAN tags end-to-end without being stripped by OVN.

* DNS

  Native implementation. Since the version 2.8 OVN contains a built-in
  DNS implementation.

* Port Forwarding

  The OVN driver supports port forwarding as an extension of floating
  IPs. Enable the 'port_forwarding' service plugin in neutron configuration
  files to use this feature.

* Packet Logging

  Packet logging service is designed as a Neutron plug-in that captures network
  packets for relevant resources when the registered events occur. OVN supports
  this feature based on security groups.

* Segments

  Allows for Network segments ranges to be used with OVN. Requires OVN
  version 20.06 or higher.

* Routed provider networks

  Allows for multiple localnet ports to be attached to a single Logical
  Switch entry. This work also assumes that only a single localnet
  port (of the same Logical Switch) is actually mapped to a given
  hypervisor. Requires OVN version 20.06 or higher.

* VPN as a Service (VPNaaS)

  The OVN driver supports VPN as a Service. Enable the 'vpnaas'
  service plugin in neutron configuration files to use this feature.

* Firewall as a Service v2 (FWaaS v2)

  The OVN driver supports Firewall as a Service v2. Enable the 'firewall_v2'
  service plugin in neutron configuration files to use this feature.

* BGP Dynamic Routing

  The OVN driver supports BGP dynamic routing. Enable the
  'bgp' service plugin in neutron configuration files to use this feature.

* Tap Mirror

  The OVN driver supports traffic mirroring using port mirroring (tap as a
  service). Enable the 'tap_mirror' service plugin in neutron configuration
  files to use this feature.

* External Gateway Multihoming

  The OVN driver supports external gateway multihoming, allowing routers to
  be connected to multiple external networks for redundancy and load
  distribution.

* QinQ

  The OVN driver supports QinQ (802.1ad) encapsulation for provider networks.

* Private VLAN (PVLAN)

  The OVN driver supports private VLAN (PVLAN) networks.


The following Neutron API extensions are supported with OVN:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Extension Name
     - Extension Alias
   * - Address Group
     - address-group
   * - Address Scope
     - address-scope
   * - Agent
     - agent
   * - Allowed Address Pairs
     - allowed-address-pairs
   * - Auto Allocated Topology Services
     - auto-allocated-topology
   * - Availability Zone
     - availability_zone
   * - BGP
     - bgp
   * - BGP 4-byte ASN
     - bgp_4byte_asn
   * - BGP DR Agent Scheduler
     - bgp_dragent_scheduler
   * - Default Subnetpools
     - default-subnetpools
   * - DHCP Agent Scheduler
     - dhcp_agent_scheduler
   * - DNS Domain for Ports
     - dns-domain-ports
   * - DNS Domain Names with Keywords
     - dns-integration-domain-keywords
   * - DNS Integration
     - dns-integration
   * - Empty String Filtering
     - empty-string-filtering
   * - Enable Default Route BFD
     - enable-default-route-bfd
   * - Enable Default Route ECMP
     - enable-default-route-ecmp
   * - Expose Port Forwarding in FIP
     - expose-port-forwarding-in-fip
   * - External Gateway Multihoming
     - external-gateway-multihoming
   * - Extra Route
     - extraroute
   * - Extra Route Atomic
     - extraroute-atomic
   * - Filter Validation
     - filter-validation
   * - FIP Port Details
     - fip-port-details
   * - FIP Port Forwarding Description
     - floating-ip-port-forwarding-description
   * - FIP Port Forwarding Detail
     - floating-ip-port-forwarding-detail
   * - FIP Port Forwarding Port Ranges
     - floating-ip-port-forwarding-port-ranges
   * - Flavors
     - flavors
   * - Floating IP Port Forwarding
     - floating-ip-port-forwarding
   * - Floating IP Pools
     - floatingip-pools
   * - Firewall as a Service v2
     - fwaas_v2
   * - IP Allocation
     - ip_allocation
   * - L3 External Gateway Mode
     - ext-gw-mode
   * - L3 Flavors
     - l3-flavors
   * - L3 HA
     - l3-ha
   * - L3 Router
     - router
   * - Multi Provider Network
     - multi-provider
   * - Network Availability Zone
     - network_availability_zone
   * - Network External
     - external-net
   * - Network HA
     - network_ha
   * - Network IP Availability
     - network-ip-availability
   * - Network MTU
     - net-mtu
   * - Network MTU Writable
     - net-mtu-writable
   * - Network Segment
     - segment
   * - Neutron Extra DHCP Opts
     - extra_dhcp_opt
   * - Packet Logging
     - logging
   * - Pagination
     - pagination
   * - Port Binding
     - binding
   * - Port Bindings Extended
     - binding-extended
   * - Port Device Profile
     - port-device-profile
   * - Port Hardware Offload Type
     - port-hardware-offload-type
   * - Port MAC Address Regenerate
     - port-mac-address-regenerate
   * - Port NUMA Affinity Policy
     - port-numa-affinity-policy
   * - Port NUMA Affinity Policy Socket
     - port-numa-affinity-policy-socket
   * - Port Resource Request
     - port-resource-request
   * - Port Security
     - port-security
   * - Port Trusted VIF
     - port-trusted-vif
   * - Private VLAN
     - pvlan
   * - Project ID
     - project-id
   * - Provider Network
     - provider
   * - QinQ
     - qinq
   * - Quality of Service
     - qos
   * - QoS Bandwidth Limit Direction
     - qos-bw-limit-direction
   * - QoS Bandwidth Minimum Ingress
     - qos-bw-minimum-ingress
   * - QoS Default
     - qos-default
   * - QoS for Floating IPs
     - qos-fip
   * - QoS Gateway IP
     - qos-gateway-ip
   * - QoS Rule Type Details
     - qos-rule-type-details
   * - QoS Rule Type Filter
     - qos-rule-type-filter
   * - QoS Rules Alias
     - qos-rules-alias
   * - Quota Check Limit
     - quota-check-limit
   * - Quota Check Limit Default
     - quota-check-limit-default
   * - Quota Details
     - quota_details
   * - Quota Management Support
     - quotas
   * - RBAC Address Scope
     - rbac-address-scope
   * - RBAC Policies
     - rbac-policies
   * - RBAC Security Groups
     - rbac-security-groups
   * - Resource Revision Numbers
     - standard-attr-revisions
   * - Router Availability Zone
     - router_availability_zone
   * - Router Enable SNAT
     - router-enable-snat
   * - Security Group
     - security-group
   * - Security Groups Default Rules
     - security-groups-default-rules
   * - Security Groups Normalized CIDR
     - security-groups-normalized-cidr
   * - Security Groups Remote Address Group
     - security-groups-remote-address-group
   * - Security Groups Rules Belongs to Default SG
     - security-groups-rules-belongs-to-default-sg
   * - Security Groups Shared Filtering
     - security-groups-shared-filtering
   * - Sorting
     - sorting
   * - Standard Attr Description
     - standard-attr-description
   * - Standard Attr FWaaS v2
     - standard-attr-fwaas-v2
   * - Standard Attr Tag
     - standard-attr-tag
   * - Standard Attr Timestamp
     - standard-attr-timestamp
   * - Stateful Security Group
     - stateful-security-group
   * - Subnet Allocation
     - subnet_allocation
   * - Subnet DNS Publish Fixed IP
     - subnet-dns-publish-fixed-ip
   * - Subnet External Network
     - subnet-external-network
   * - Subnet Onboard
     - subnet_onboard
   * - Subnet Service Types
     - subnet-service-types
   * - Subnetpool Prefix Ops
     - subnetpool-prefix-ops
   * - Tag Creation
     - tag-creation
   * - Tap Mirror
     - tap-mirror
   * - Tap Mirror Both Direction
     - tap-mirror-both-direction
   * - Trunk
     - trunk
   * - Uplink Status Propagation
     - uplink-status-propagation
   * - Uplink Status Propagation Updatable
     - uplink-status-propagation-updatable
   * - VLAN Transparent
     - vlan-transparent
   * - VPN as a Service
     - vpnaas
   * - VPN Endpoint Groups
     - vpn-endpoint-groups
