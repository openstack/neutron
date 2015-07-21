======================================
L2 Networking with SR-IOV enabled NICs
======================================
SR-IOV (Single Root I/O Virtualization) is a specification that allows
a PCIe device to appear to be multiple separate physical PCIe devices.
SR-IOV works by introducing the idea of physical functions (PFs) and virtual functions (VFs).
Physical functions (PFs) are full-featured PCIe functions.
Virtual functions (VFs) are “lightweight” functions that lack configuration resources.

SR-IOV supports VLANs for L2 network isolation, other networking technologies
such as VXLAN/GRE may be supported in the future.

SR-IOV NIC agent manages configuration of SR-IOV Virtual Functions that connect
VM instances running on the compute node to the public network.

In most common deployments, there are compute and a network nodes.
Compute node can support VM connectivity via SR-IOV enabled NIC. SR-IOV NIC Agent manages
Virtual Functions admin state. In the future it will manage additional settings, such as
quality of service, rate limit settings, spoofcheck and more.
Network node will be usually deployed with either Open vSwitch or Linux Bridge to support network node functionality.


Further Reading
---------------

* `Nir Yechiel - SR-IOV Networking – Part I: Understanding the Basics <http://redhatstackblog.redhat.com/2015/03/05/red-hat-enterprise-linux-openstack-platform-6-sr-iov-networking-part-i-understanding-the-basics/>`_
* `SR-IOV Passthrough For Networking <https://wiki.openstack.org/wiki/SR-IOV-Passthrough-For-Networking/>`_
