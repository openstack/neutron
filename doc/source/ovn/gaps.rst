.. _ovn_gaps:

Gaps from ML2/OVS
=================

This is a list of some of the currently known gaps between ML2/OVS and OVN.
It is not a complete list, but is enough to be used as a starting point for
implementors working on closing these gaps. A TODO list for OVN is located
at [1]_.

* Baremetal provisioning with iPXE without Neutron DHCP agent for IPv6

  The core OVN built-in DHCP server implementation does not
  yet support PXE booting for IPv6. This can be achieved at
  the moment if used with the Neutron DHCP agent by deploying it
  on OVN gateway nodes and disabling the OVN DHCP by setting the
  ``[ovn]/disable_ovn_dhcp_for_baremetal_ports`` configuration option
  to True.

* QoS minimum bandwidth allocation in Placement API

  ML2/OVN integration with the Nova placement API to provide guaranteed
  minimum bandwidth for ports [2]_. Work in progress, see [3]_

* IPv6 Prefix Delegation

  Currently ML2/OVN doesn't implement IPv6 prefix delegation. OVN logical
  routers have this capability implemented in [4]_ and we have an open RFE to
  fill this gap [5]_.

* East/West Fragmentation

  The core OVN implementation does not support east/west fragmentation. There is
  no known production use-case for this feature hence we don't even have an RFE
  open for it and it's not on the roadmap to be implemented.

* DHCP service for instances

  ML2/OVS adds packet filtering rules to every instance that allow DHCP queries
  from instances to reach the DHCP agent. For OVN this traffic has to be explicitly
  allowed by security group rules attached to the instance. Note that the default
  security group does allow all outgoing traffic, so this only becomes relevant
  when using custom security groups [6]_. Proposed patch is [7]_ but it
  needs to be revived and updated.

* DNS resolution for instances

  OVN cannot use the host's networking for DNS resolution, so Case 2b in [8]_ can
  only be used when additional DHCP agents are deployed. For Case 2a a different
  configuration option has to be used in ``ml2_conf.ini``::

    [ovn]
    dns_servers = 203.0.113.8, 198.51.100.53

  OVN answers queries for hosts and IP addresses in tenant networks by spoofing
  responses from the configured DNS servers. This may lead to confusion in
  debugging.

  OVN can only answer queries that are sent via UDP, queries that use TCP will be
  ignored by OVN and forwarded to the configured resolvers.

  OVN can only answer queries with no additional options being set (EDNS). Such
  queries depending on the OVN version will either get broken responses or will
  also be forwarded to the configured resolvers.

* IPv6 NDP proxy

  The NDP proxy functionality for IPv6 addresses is not supported by OVN.

* Metadata via IPv6

  The OVN metadata agent currently does not allow access via IPv6.

References
----------

.. [1] https://github.com/ovn-org/ovn/blob/master/TODO.rst
.. [2] https://specs.openstack.org/openstack/neutron-specs/specs/rocky/minimum-bandwidth-allocation-placement-api.html
.. [3] https://review.opendev.org/c/openstack/neutron/+/786478
.. [4] https://patchwork.ozlabs.org/project/openvswitch/patch/6aec0fb280f610a2083fbb6c61e251b1d237b21f.1576840560.git.lorenzo.bianconi@redhat.com/
.. [5] https://bugs.launchpad.net/neutron/+bug/1895972
.. [6] https://bugs.launchpad.net/neutron/+bug/1926515
.. [7] https://review.opendev.org/c/openstack/neutron/+/788594
.. [8] https://docs.openstack.org/neutron/latest/admin/config-dns-res.html
