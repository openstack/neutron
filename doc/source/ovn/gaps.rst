.. _ovn_gaps:

Gaps from ML2/OVS
=================

This is a list of some of the currently known gaps between ML2/OVS and OVN.
It is not a complete list, but is enough to be used as a starting point for
implementors working on closing these gaps. A TODO list for OVN is located
at [1]_.

* Port forwarding

  Currently ML2/OVS supports Port Forwarding in the North/South plane.
  Specific L4 Ports of the Floating IP can be directed to a specific
  FixedIP:PortNumber of a VM, so that different services running in a VM
  can be isolated, and can communicate with external networks easily.

  This is a relatively new extension, support would need to be added to OVN.

  One possible way would be to use the OVN native load balancing feature.
  An OVN load balancer is expressed in the OVN northbound load_balancer
  table. Normally the VIP and its members are expressed as [2]_:

  .. code-block:: console

     VIP:PORT = MEMBER1:MPORT1, MEMBER2:MPORT2

     The same could be extended for port forwarding as:

     FIP:PORT = PRIVATE_IP:PRIV_PORT

* Security Groups logging API

  Currently ML2/OVS, with the OpenvSwitch firewall, supports a log file where
  security groups events are logged to be consumed by a security entity. This
  allows users to have a way to check if an instance is trying to execute
  restricted operations, or access restricted ports in remote servers.

  This is a relatively new extension, support would need to be added to OVN.

* QoS DSCP support

  Currently ML2/OVS supports QoS DSCP tagging and egress bandwidth limiting.
  Those are basic QoS features that while integrated in the OVS/OVN C core
  are not integrated (or fully tested) in the neutron OVN mechanism driver.

* QoS for Layer 3 IPs

  Currently the Neutron L3-agent supports floating IP and gateway IP bandwidth
  limiting based on Linux TC. Networking-ovn L3 had a prototype
  implementation [3]_ based on the meter of openvswitch [4]_ utility that
  has been abandoned. This is supported in user space datapath only, or
  kernel versions 4.15+ [5]_.

* QoS Minimum Bandwidth support

  Currently ML2/OVS supports QoS Minimum Bandwidth limiting, but it is
  not supported in OVN.

* BGP support

  Currently ML2/OVS supports making a tenant subnet routable via BGP, and
  can announce host routes for both floating and fixed IP addresses.

References
----------

.. [1] https://github.com/ovn-org/ovn/blob/master/TODO.rst
.. [2] https://github.com/ovn-org/ovn/blob/master/ovn-nb.ovsschema#L160
.. [3] https://review.opendev.org/#/c/539826/
.. [4] https://github.com/openvswitch/ovs/commit/66d89287269ca7e2f7593af0920e910d7f9bcc38
.. [5] https://github.com/torvalds/linux/blob/master/net/openvswitch/meter.h
