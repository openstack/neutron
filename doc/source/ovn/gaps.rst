.. _ovn_gaps:

Gaps from ML2/OVS
=================

This is a list of some of the currently known gaps between ML2/OVS and OVN.
It is not a complete list, but is enough to be used as a starting point for
implementors working on closing these gaps. A TODO list for OVN is located
at [1]_.

* QoS Minimum Bandwidth support

  Currently ML2/OVS supports QoS Minimum Bandwidth limiting, but it is
  not supported in OVN.
  The work on this is in progress. Details can be found at [2]_ and [3]_.

* BGP support

  Neutron-dynamic-routing supports making a tenant subnet routable via BGP, and
  can announce host routes for both floating and fixed IP addresses. These
  functions are not supported in OVN.

* Baremetal provisioning with iPXE

  The core OVN DHCP server implementation does not have support for
  sending different boot options based on the ``gpxe`` DHCP Option
  (no. 175). Also, Ironic uses dnsmasq syntax when configuring the DHCP
  options for Neutron [4]_ which is not understood by the OVN driver.
  Work on that is in progress currently, see [5]_ and [6]_.

* QoS minimum bandwidth allocation in Placement API

  ML2/OVN integration with the Nova placement API to provide guaranteed
  minimum bandwidth for ports [7]_. Work in progress, see [8]_

* IPv6 Prefix Delegation

  Currently ML2/OVN doesn't implement IPv6 prefix delegation. OVN logical
  routers have this capability implemented in [9]_ and we have an open RFE to
  fill this gap [10]_.

* East/West Fragmentation

  The core OVN implementation does not support east/west fragmentation. There is
  no known production use-case for this feature hence we don't even have an RFE
  open for it and it's not on the roadmap to be implemented.

* DHCP service for instances

  ML2/OVS adds packet filtering rules to every instance that allow DHCP queries
  from instances to reach the DHCP agent. For OVN this traffic has to be explicitly
  allowed by security group rules attached to the instance. Note that the default
  security group does allow all outgoing traffic, so this only becomes relevant
  when using custom security groups [11]_. Proposed patch is [12]_ but it
  needs to be revived and updated.

* DNS resolution for instances

  OVN cannot use the host's networking for DNS resolution, so Case 2b in [13]_ can
  only be used when additional DHCP agents are deployed. For Case 2a a different
  configuration option has to be used in ``ml2_conf.ini``::

    [ovn]
    dns_servers = 203.0.113.8, 198.51.100.53

References
----------

.. [1] https://github.com/ovn-org/ovn/blob/master/TODO.rst
.. [2] https://bugzilla.redhat.com/show_bug.cgi?id=2060310
.. [3] https://review.opendev.org/c/openstack/neutron/+/842292
.. [4] https://github.com/openstack/ironic/blob/123cb22c731f93d0c608d791b41e05884fe18c04/ironic/common/pxe_utils.py#L447-L462>
.. [5] https://review.opendev.org/c/openstack/neutron/+/840287
.. [6] https://review.opendev.org/c/openstack/neutron/+/840316
.. [7] https://specs.openstack.org/openstack/neutron-specs/specs/rocky/minimum-bandwidth-allocation-placement-api.html
.. [8] https://review.opendev.org/c/openstack/neutron/+/786478
.. [9] https://patchwork.ozlabs.org/project/openvswitch/patch/6aec0fb280f610a2083fbb6c61e251b1d237b21f.1576840560.git.lorenzo.bianconi@redhat.com/
.. [10] https://bugs.launchpad.net/neutron/+bug/1895972
.. [11] https://bugs.launchpad.net/neutron/+bug/1926515
.. [12] https://review.opendev.org/c/openstack/neutron/+/788594
.. [13] https://docs.openstack.org/neutron/latest/admin/config-dns-res.html
