.. _config-ovs-dpdk:

===============================
Open vSwitch with DPDK datapath
===============================

This page serves as a guide for how to use the OVS with DPDK datapath
functionality available in the Networking service as of the Mitaka release.

The basics
~~~~~~~~~~

Open vSwitch (OVS) provides support for a Data Plane Development Kit (DPDK)
datapath since OVS 2.2, and a DPDK-backed ``vhost-user`` virtual interface
since OVS 2.4. The DPDK datapath provides lower latency and higher performance
than the standard kernel OVS datapath, while DPDK-backed ``vhost-user``
interfaces can connect guests to this datapath. For more information on DPDK,
refer to the `DPDK <http://dpdk.org/>`__ website.

OVS with DPDK, or OVS-DPDK, can be used to provide high-performance networking
between instances on OpenStack compute nodes.

Prerequisites
-------------

Using DPDK in OVS requires the following minimum software versions:

* OVS 2.4
* DPDK 2.0
* QEMU 2.1.0
* libvirt 1.2.13

Support of ``vhost-user`` multiqueue that enables use of multiqueue with
``virtio-net`` and ``igb_uio`` is available if the following newer
versions are used:

* OVS 2.5
* DPDK 2.2
* QEMU 2.5
* libvirt 1.2.17

In both cases, install and configure Open vSwitch with DPDK support for each
node. For more information, see the
`OVS-DPDK <https://github.com/openvswitch/ovs/blob/master/Documentation/intro/install/dpdk.rst>`__
installation guide (select an appropriate OVS version in the
:guilabel:`Branch` drop-down menu).

:doc:`/contributor/internals/ovs_vhostuser`
for configuration of neutron OVS agent.

In case you wish to configure multiqueue, see the
`OVS configuration chapter on vhost-user
<http://wiki.qemu.org/Documentation/vhost-user-ovs-dpdk#Enabling_multi-queue>`__
in QEMU documentation.

The technical background of multiqueue is explained in the corresponding
`blueprint <https://specs.openstack.org/openstack/nova-specs/specs/liberty/implemented/libvirt-virtiomq.html>`__.

Additionally, OpenStack supports ``vhost-user`` reconnect feature starting
from the Ocata release, as implementation of fix for
`bug 1604924 <https://bugs.launchpad.net/neutron/+bug/1604924>`__.
Starting from OpenStack Ocata release this feature is used without any
configuration necessary in case the following minimum software versions
are used:

* OVS 2.6
* DPDK 16.07
* QEMU 2.7

The support of this feature is not yet present in ML2 OVN and ODL
mechanism drivers.

Using vhost-user interfaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once OVS and neutron are correctly configured with DPDK support,
``vhost-user`` interfaces are completely transparent to the guest
(except in case of multiqueue configuration described below).
However, guests must request huge pages. This can be done through flavors.
For example:

.. code-block:: console

   $ openstack flavor set m1.large --property hw:mem_page_size=large

For more information about the syntax for ``hw:mem_page_size``, refer to the
`Flavors <https://docs.openstack.org/nova/latest/admin/flavors.html>`__ guide.

.. note::

   ``vhost-user`` requires file descriptor-backed shared memory. Currently, the
   only way to request this is by requesting large pages. This is why instances
   spawned on hosts with OVS-DPDK must request large pages. The aggregate
   flavor affinity filter can be used to associate flavors with large page
   support to hosts with OVS-DPDK support.

Create and add ``vhost-user`` network interfaces to instances in the same
fashion as conventional interfaces. These interfaces can use the kernel
``virtio-net`` driver or a DPDK-compatible driver in the guest

.. code-block:: console

   $ openstack server create --nic net-id=$net_id ... testserver

Using vhost-user multiqueue
~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use this feature, the following should be set in the flavor extra specs
(flavor keys):

.. code-block:: console

   $ openstack flavor set $m1.large --property hw:vif_multiqueue_enabled=true

This setting can be overridden by the image metadata property if the feature
is enabled in the extra specs:

.. code-block:: console

   $ openstack image set --property hw_vif_multiqueue_enabled=true IMAGE_NAME

Support of ``virtio-net`` multiqueue needs to be present in kernel of
guest VM and is available starting from Linux kernel 3.8.

Check pre-set maximum for number of combined channels in channel
configuration.
Configuration of OVS and flavor done successfully should result in
maximum being more than '1'):

.. code-block:: console

  $ ethtool -l INTERFACE_NAME

To increase number of current combined channels run following command in
guest VM:

.. code-block:: console

  $ ethtool -L INTERFACE_NAME combined QUEUES_NR

The number of queues should typically match the number of vCPUs
defined for the instance. In newer kernel versions
this is configured automatically.

Known limitations
~~~~~~~~~~~~~~~~~

* This feature is only supported when using the libvirt compute driver, and the
  KVM/QEMU hypervisor.
* Huge pages are required for each instance running on hosts with OVS-DPDK.
  If huge pages are not present in the guest, the interface will appear but
  will not function.
* Expect performance degradation of services using tap devices: these devices
  do not support DPDK. Example services include DVR, FWaaS, or LBaaS.
