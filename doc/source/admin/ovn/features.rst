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
  conventional Neutron L3 agent. This includes transparent L3HA :doc::`routing`
  support, based on BFD monitorization integrated in core OVN.

* DHCP

  Native distributed implementation.  Replaces the conventional Neutron DHCP
  agent.  Note that the native implementation does not yet support DNS
  features.

* DPDK

  OVN and ovn mechanism driver may be used with OVS using either the Linux
  kernel datapath or the DPDK datapath.

* Trunk driver

  Uses OVN's functionality of parent port and port tagging to support trunk
  service plugin. One has to enable the 'trunk' service plugin in neutron
  configuration files to use this feature.

* VLAN tenant networks

  The ovn driver does support VLAN tenant networks when used
  with OVN version 2.11 (or higher).

* DNS

  Native implementation. Since the version 2.8 OVN contains a built-in
  DNS implementation.


The following Neutron API extensions are supported with OVN:

+----------------------------------+---------------------------+
| Extension Name                   | Extension Alias           |
+==================================+===========================+
| Allowed Address Pairs            | allowed-address-pairs     |
+----------------------------------+---------------------------+
| Auto Allocated Topology Services | auto-allocated-topology   |
+----------------------------------+---------------------------+
| Availability Zone                | availability_zone         |
+----------------------------------+---------------------------+
| Default Subnetpools              | default-subnetpools       |
+----------------------------------+---------------------------+
| Multi Provider Network           | multi-provider            |
+----------------------------------+---------------------------+
| Network IP Availability          | network-ip-availability   |
+----------------------------------+---------------------------+
| Neutron external network         | external-net              |
+----------------------------------+---------------------------+
| Neutron Extra DHCP opts          | extra_dhcp_opt            |
+----------------------------------+---------------------------+
| Neutron Extra Route              | extraroute                |
+----------------------------------+---------------------------+
| Neutron L3 external gateway      | ext-gw-mode               |
+----------------------------------+---------------------------+
| Neutron L3 Router                | router                    |
+----------------------------------+---------------------------+
| Network MTU                      | net-mtu                   |
+----------------------------------+---------------------------+
| Port Binding                     | binding                   |
+----------------------------------+---------------------------+
| Port Security                    | port-security             |
+----------------------------------+---------------------------+
| Provider Network                 | provider                  |
+----------------------------------+---------------------------+
| Quality of Service               | qos                       |
+----------------------------------+---------------------------+
| Quota management support         | quotas                    |
+----------------------------------+---------------------------+
| RBAC Policies                    | rbac-policies             |
+----------------------------------+---------------------------+
| Resource revision numbers        | standard-attr-revisions   |
+----------------------------------+---------------------------+
| security-group                   | security-group            |
+----------------------------------+---------------------------+
| standard-attr-description        | standard-attr-description |
+----------------------------------+---------------------------+
| Subnet Allocation                | subnet_allocation         |
+----------------------------------+---------------------------+
| Tag support                      | standard-attr-tag         |
+----------------------------------+---------------------------+
| Time Stamp Fields                | standard-attr-timestamp   |
+----------------------------------+---------------------------+
| Domain Name System (DNS)         | dns_integration           |
+----------------------------------+---------------------------+
