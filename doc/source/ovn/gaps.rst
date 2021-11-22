.. _ovn_gaps:

Gaps from ML2/OVS
=================

This is a list of some of the currently known gaps between ML2/OVS and OVN.
It is not a complete list, but is enough to be used as a starting point for
implementors working on closing these gaps. A TODO list for OVN is located
at [1]_.

* QoS DSCP support

  Currently ML2/OVS supports QoS DSCP tagging and egress bandwidth limiting.
  Those are basic QoS features that while integrated in the OVS/OVN C core
  are not integrated (or fully tested) in the neutron OVN mechanism driver.

* QoS for Layer 3 IPs

  Currently the Neutron L3-agent supports floating IP and gateway IP bandwidth
  limiting based on Linux TC. OVN L3 plugin supports floating IP bandwidth
  limiting based on the OVN's QoS rules.
  Neutron OVN backend does not yet support bandwidth limiting for gateway IP.

* QoS Minimum Bandwidth support

  Currently ML2/OVS supports QoS Minimum Bandwidth limiting, but it is
  not supported in OVN.

* BGP support

  Neutron-dynamic-routing supports making a tenant subnet routable via BGP, and
  can announce host routes for both floating and fixed IP addresses. These
  functions are not supported in OVN.

* Baremetal provisioning with iPXE

  The core OVN DHCP server implementation does not have support for
  sending different boot options based on the ``gpxe`` DHCP Option
  (no. 175). Also, Ironic uses dnsmasq syntax when configuring the DHCP
  options for Neutron [2]_ which is not understood by the OVN driver.

* QoS minimum bandwidth allocation in Placement API

  ML2/OVN integration with the Nova placement API to provide guaranteed
  minimum bandwidth for ports [3]_.

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
  when using custom security groups [6]_.

* DNS resolution for instances

  OVN cannot use the host's networking for DNS resolution, so Case 2b in [7]_ can
  only be used when additional DHCP agents are deployed. For Case 2a a different
  configuration option has to be used in ``ml2_conf.ini``::

    [ovn]
    dns_servers = 203.0.113.8, 198.51.100.53

  Note that this option currently only works for IPv4 nameservers [8]_.
  In addition, with ML2/OVS setting the name-server option for a subnet to ``0.0.0.0``
  or ``::`` respectively has the effect that no nameservers are announced via DHCP for
  this subnet. This currently does not work with OVN [9]_.

References
----------

.. [1] https://github.com/ovn-org/ovn/blob/master/TODO.rst
.. [2] https://github.com/openstack/ironic/blob/123cb22c731f93d0c608d791b41e05884fe18c04/ironic/common/pxe_utils.py#L447-L462>
.. [3] https://specs.openstack.org/openstack/neutron-specs/specs/rocky/minimum-bandwidth-allocation-placement-api.html
.. [4] https://patchwork.ozlabs.org/project/openvswitch/patch/6aec0fb280f610a2083fbb6c61e251b1d237b21f.1576840560.git.lorenzo.bianconi@redhat.com/
.. [5] https://bugs.launchpad.net/neutron/+bug/1895972
.. [6] https://bugs.launchpad.net/neutron/+bug/1926515
.. [7] https://docs.openstack.org/neutron/latest/admin/config-dns-res.html
.. [8] https://bugs.launchpad.net/neutron/+bug/1951816
.. [9] https://bugs.launchpad.net/neutron/+bug/1950686
