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

  OVN and the OVN mechanism driver may be used with OVS using either the Linux
  kernel datapath or the DPDK datapath.

* Trunk driver

  Uses OVN's functionality of parent port and port tagging to support trunk
  service plugin. One has to enable the 'trunk' service plugin in neutron
  configuration files to use this feature.

* VLAN tenant networks

  The OVN driver does support VLAN tenant networks when used
  with OVN version 2.11 (or higher).

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

.. TODO What about tenant networks?

* Routed provider networks

  Allows for multiple localnet ports to be attached to a single Logical
  Switch entry. This work also assumes that only a single localnet
  port (of the same Logical Switch) is actually mapped to a given
  hypervisor. Requires OVN version 20.06 or higher.


The following Neutron API extensions are supported with OVN:

+----------------------------------+---------------------------------+
| Extension Name                   | Extension Alias                 |
+==================================+=================================+
| Allowed Address Pairs            | allowed-address-pairs           |
+----------------------------------+---------------------------------+
| Auto Allocated Topology Services | auto-allocated-topology         |
+----------------------------------+---------------------------------+
| Availability Zone                | availability_zone               |
+----------------------------------+---------------------------------+
| Default Subnetpools              | default-subnetpools             |
+----------------------------------+---------------------------------+
| DNS Integration                  | dns-integration                 |
+----------------------------------+---------------------------------+
| DNS domain for ports             | dns-domain-ports                |
+----------------------------------+---------------------------------+
| DNS domain names with keywords   | dns-integration-domain-keywords |
+----------------------------------+---------------------------------+
| Subnet DNS publish fixed IP      | subnet-dns-publish-fixed-ip     |
+----------------------------------+---------------------------------+
| Multi Provider Network           | multi-provider                  |
+----------------------------------+---------------------------------+
| Network IP Availability          | network-ip-availability         |
+----------------------------------+---------------------------------+
| Network Segment                  | segment                         |
+----------------------------------+---------------------------------+
| Neutron external network         | external-net                    |
+----------------------------------+---------------------------------+
| Neutron Extra DHCP opts          | extra_dhcp_opt                  |
+----------------------------------+---------------------------------+
| Neutron Extra Route              | extraroute                      |
+----------------------------------+---------------------------------+
| Neutron L3 external gateway      | ext-gw-mode                     |
+----------------------------------+---------------------------------+
| Neutron L3 Router                | router                          |
+----------------------------------+---------------------------------+
| Network MTU                      | net-mtu                         |
+----------------------------------+---------------------------------+
| Packet Logging                   | logging                         |
+----------------------------------+---------------------------------+
| Port Binding                     | binding                         |
+----------------------------------+---------------------------------+
| Port Bindings Extended           | binding-extended                |
+----------------------------------+---------------------------------+
| Port Forwarding                  | port_forwarding                 |
+----------------------------------+---------------------------------+
| Port MAC address Regenerate      | port-mac-address-regenerate     |
+----------------------------------+---------------------------------+
| Port Security                    | port-security                   |
+----------------------------------+---------------------------------+
| Provider Network                 | provider                        |
+----------------------------------+---------------------------------+
| Quality of Service               | qos                             |
+----------------------------------+---------------------------------+
| Quota management support         | quotas                          |
+----------------------------------+---------------------------------+
| RBAC Policies                    | rbac-policies                   |
+----------------------------------+---------------------------------+
| Resource revision numbers        | standard-attr-revisions         |
+----------------------------------+---------------------------------+
| security-group                   | security-group                  |
+----------------------------------+---------------------------------+
| standard-attr-description        | standard-attr-description       |
+----------------------------------+---------------------------------+
| Subnet Allocation                | subnet_allocation               |
+----------------------------------+---------------------------------+
| Subnet service types             | subnet-service-types            |
+----------------------------------+---------------------------------+
| Tag support                      | standard-attr-tag               |
+----------------------------------+---------------------------------+
| Time Stamp Fields                | standard-attr-timestamp         |
+----------------------------------+---------------------------------+
