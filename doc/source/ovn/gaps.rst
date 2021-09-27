.. _ovn_gaps:

Gaps from ML2/OVS
=================

This is a list of some of the currently known gaps between ML2/OVS and OVN.
It is not a complete list, but is enough to be used as a starting point for
implementors working on closing these gaps. A TODO list for OVN is located
at [1]_.

* QoS DSCP support

  Currently the Neutron L3-agent supports floating IP and gateway IP bandwidth
  limiting based on Linux TC. OVN L3 plugin supports floating IP bandwidth
  limiting based on the OVN's QoS rules.
  Neutron OVN backend does not yet support bandwidth limiting for gateway IP.

* QoS for Layer 3 IPs

  Currently the Neutron L3-agent supports floating IP and gateway IP bandwidth
  limiting based on Linux TC. Networking-ovn L3 had a prototype
  implementation [2]_ based on the meter of openvswitch [3]_ utility that
  has been abandoned. This is supported in user space datapath only, or
  kernel versions 4.15+ [4]_.

* QoS Minimum Bandwidth support

  Currently ML2/OVS supports QoS Minimum Bandwidth limiting, but it is
  not supported in OVN.

* BGP support

  Currently ML2/OVS supports making a tenant subnet routable via BGP, and
  can announce host routes for both floating and fixed IP addresses.

* Baremetal provisioning with iPXE

  The core OVN DHCP server implementation does not have support for
  sending different boot options based on the ``gpxe`` DHCP Option
  (no. 175). Also, Ironic uses dnsmasq syntax when configuring the DHCP
  options for Neutron [5]_ which is not understood by the OVN driver.

* Availability Zones

  Availability zones are used to make network resources highly available
  by grouping nodes in separate zones which resources will be scheduled
  to. Neutron supports two types of availability zones: Network (DHCP
  agent) and router (L3 agent). The OVN team needs to assess each case
  to see how they would fit in the OVN model. For example, in the router
  availability zone case, the OVN driver should schedule the router
  ports on a Chassis (a "node" in OVN terms) where the availability
  zones match with the router availability zones [6]_.

* QoS minimum bandwidth allocation in Placement API

  ML2/OVN integration with the Nova placement API to provide guaranteed
  minimum bandwidth for ports [7]_.

* IPv6 Prefix Delegation

  Currently ML2/OVN doesn't implement IPv6 prefix delegation. OVN logical
  routers have this capability implemented in [8]_ and we have an open RFE to
  fill this gap [9]_.

* East/West Fragmentation

  The core OVN implementation does not support east/west fragmentation. There is
  no known production use-case for this feature hence we don't even have an RFE
  open for it and it's not on the roadmap to be implemented.


References
----------

.. [1] https://github.com/ovn-org/ovn/blob/master/TODO.rst
.. [2] https://review.opendev.org/#/c/539826/
.. [3] https://github.com/openvswitch/ovs/commit/66d89287269ca7e2f7593af0920e910d7f9bcc38
.. [4] https://github.com/torvalds/linux/blob/master/net/openvswitch/meter.h
.. [5] https://github.com/openstack/ironic/blob/123cb22c731f93d0c608d791b41e05884fe18c04/ironic/common/pxe_utils.py#L447-L462>
.. [6] https://docs.openstack.org/neutron/latest/admin/config-az.html
.. [7] https://specs.openstack.org/openstack/neutron-specs/specs/rocky/minimum-bandwidth-allocation-placement-api.html
.. [8] https://patchwork.ozlabs.org/project/openvswitch/patch/6aec0fb280f610a2083fbb6c61e251b1d237b21f.1576840560.git.lorenzo.bianconi@redhat.com/
.. [9] https://bugs.launchpad.net/neutron/+bug/1895972
