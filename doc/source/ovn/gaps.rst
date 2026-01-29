.. _ovn_gaps:

Gaps from ML2/OVS
=================

This is a list of some of the currently known gaps between ML2/OVS and OVN.
It is not a complete list, but is enough to be used as a starting point for
implementors working on closing these gaps. A TODO list for OVN is located
at [1]_.

* DHCP service for instances

  ML2/OVS adds packet filtering rules to every instance that allow DHCP queries
  from instances to reach the DHCP agent. For OVN this traffic has to be
  explicitly allowed by security group rules attached to the instance. Note
  that the default security group does allow all outgoing traffic, so this only
  becomes relevant when using custom security groups [2]_. Proposed patch is
  [3]_ but it needs to be revived and updated.

* DNS resolution for instances

  OVN cannot use the host's networking for DNS resolution, so Case 2b in [4]_
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
  tracked in [5]_ and [6]_.

* Traffic metering

  Currently ``neutron-metering-agent`` can only work with the Neutron L3 agent.
  It is not supported by the ``ovn-router`` service plugin nor by the
  ``neutron-ovn-agent``. This is being reported and tracked in [7]_.

* Floating IP Port Forwarding in provider networks and with distributed routing

  Currently, when provider network types like ``vlan`` or ``flat`` are plugged
  to a router as internal networks while the ``enable_distributed_floating_ip``
  configuration option is enabled, Floating IP port forwardings
  which are using such router will not work properly.
  Due to an incompatible setting of the router to make traffic in the vlan/flat
  networks to be distributed but port forwardings are always centralized in
  ML2/OVN backend.
  This is being reported in [8]_.

References
----------

.. [1] https://github.com/ovn-org/ovn/blob/master/TODO.rst
.. [2] https://bugs.launchpad.net/neutron/+bug/1926515
.. [3] https://review.opendev.org/c/openstack/neutron/+/788594
.. [4] https://docs.openstack.org/neutron/latest/admin/config-dns-res.html
.. [5] https://bugs.launchpad.net/neutron/+bug/2032817
.. [6] https://bugzilla.redhat.com/show_bug.cgi?id=2238494
.. [7] https://bugs.launchpad.net/neutron/+bug/2048773
.. [8] https://bugs.launchpad.net/neutron/+bug/2028846
