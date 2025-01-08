.. _ovn_gaps:

Gaps from ML2/OVS
=================

This is a list of some of the currently known gaps between ML2/OVS and OVN.
It is not a complete list, but is enough to be used as a starting point for
implementors working on closing these gaps. A TODO list for OVN is located
at [1]_.

* QoS minimum bandwidth allocation in Placement API

  ML2/OVN integration with the Nova placement API to provide guaranteed
  minimum bandwidth for ports [2]_. Work in progress, see [3]_

* DHCP service for instances

  ML2/OVS adds packet filtering rules to every instance that allow DHCP queries
  from instances to reach the DHCP agent. For OVN this traffic has to be
  explicitly allowed by security group rules attached to the instance. Note
  that the default security group does allow all outgoing traffic, so this only
  becomes relevant when using custom security groups [4]_. Proposed patch is
  [5]_ but it needs to be revived and updated.

* DNS resolution for instances

  OVN cannot use the host's networking for DNS resolution, so Case 2b in [6]_
  can only be used when additional DHCP agents are deployed. For Case 2a a
  different configuration option has to be used in ``ml2_conf.ini``::

    [ovn]
    dns_servers = 203.0.113.8, 198.51.100.53

  OVN answers queries for hosts and IP addresses in tenant networks by spoofing
  responses from the configured DNS servers. This may lead to confusion in
  debugging.

  OVN can only answer queries that are sent via UDP, queries that use TCP will
  be ignored by OVN and forwarded to the configured resolvers.

  OVN can only answer queries with no additional options being set (EDNS). Such
  queries depending on the OVN version will either get broken responses or will
  also be forwarded to the configured resolvers.

* IPv6 NDP proxy

  The NDP proxy functionality for IPv6 addresses is not supported by OVN.

* East/West Fragmentation

  The core OVN implementation does not support fragmentation of East/West
  traffic using an OVN router between two private networks. This is being
  tracked in [7]_ and [8]_.

* North/South Fragmentation and path MTU discovery

  OVN does not correctly fragment IPv4 packets when the MTU of the target
  network is smaller than the MTU of the source network. Instead, affected
  packets could be silently dropped depending on the direction. OVN will
  also not generate ICMP "packet too big" responses for packets that have
  the DF bit set, even when the necessary configuration option is used
  in ``ml2_conf.ini``::

    [ovn]
    ovn_emit_need_to_frag = true

  This makes path MTU discovery fail, and is being tracked in [7]_ and [9]_.

* Traffic metering

  Currently ``neutron-metering-agent`` can only work with the Neutron L3 agent.
  It is not supported by the ``ovn-router`` service plugin nor by the
  ``neutron-ovn-agent``. This is being reported and tracked in [10]_.

* Floating IP Port Forwarding in provider networks and with distributed routing

  Currently, when provider network types like ``vlan`` or ``flat`` are plugged
  to a router as internal networks while the ``enable_distributed_floating_ip``
  configuration option is enabled, Floating IP port forwardings
  which are using such router will not work properly.
  Due to an incompatible setting of the router to make traffic in the vlan/flat
  networks to be distributed but port forwardings are always centralized in
  ML2/OVN backend.
  This is being reported in [11]_.

References
----------

.. [1] https://github.com/ovn-org/ovn/blob/master/TODO.rst
.. [2] https://specs.openstack.org/openstack/neutron-specs/specs/rocky/minimum-bandwidth-allocation-placement-api.html
.. [3] https://review.opendev.org/c/openstack/neutron/+/786478
.. [4] https://bugs.launchpad.net/neutron/+bug/1926515
.. [5] https://review.opendev.org/c/openstack/neutron/+/788594
.. [6] https://docs.openstack.org/neutron/latest/admin/config-dns-res.html
.. [7] https://bugs.launchpad.net/neutron/+bug/2032817
.. [8] https://bugzilla.redhat.com/show_bug.cgi?id=2238494
.. [9] https://bugzilla.redhat.com/show_bug.cgi?id=2238969
.. [10] https://bugs.launchpad.net/neutron/+bug/2048773
.. [11] https://bugs.launchpad.net/neutron/+bug/2028846
