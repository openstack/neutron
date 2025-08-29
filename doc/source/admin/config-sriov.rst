.. _config-sriov:

======
SR-IOV
======

The purpose of this page is to describe how to enable SR-IOV functionality
available in OpenStack (using OpenStack Networking). This functionality was
first introduced in the OpenStack Juno release. This page intends to serve as
a guide for how to configure OpenStack Networking and OpenStack Compute to
create SR-IOV ports.

The basics
~~~~~~~~~~

PCI-SIG Single Root I/O Virtualization and Sharing (SR-IOV) functionality is
available in OpenStack since the Juno release. The SR-IOV specification
defines a standardized mechanism to virtualize PCIe devices. This mechanism
can virtualize a single PCIe Ethernet controller to appear as multiple PCIe
devices. Each device can be directly assigned to an instance, bypassing the
hypervisor and virtual switch layer. As a result, users are able to achieve
low latency and near-line wire speed.

The following terms are used throughout this document:

.. list-table::
   :header-rows: 1
   :widths: 10 90

   * - Term
     - Definition
   * - PF
     - Physical Function. The physical Ethernet controller that supports
       SR-IOV.
   * - VF
     - Virtual Function. The virtual PCIe device created from a physical
       Ethernet controller.

SR-IOV agent
------------

The SR-IOV agent allows you to set the admin state of ports, configure port
security (enable and disable spoof checking), and configure QoS rate limiting
and minimum bandwidth. You must include the SR-IOV agent on each compute node
using SR-IOV ports.

.. note::

   The SR-IOV agent was optional before Mitaka, and was not enabled by default
   before Liberty.

.. note::

   The ability to control port security and QoS rate limit settings was added
   in Liberty.

Supported Ethernet controllers
------------------------------

The following manufacturers are known to work:

- Intel
- Mellanox
- QLogic
- Broadcom

For information on **Mellanox SR-IOV Ethernet ConnectX cards**, see the
`Mellanox: How To Configure SR-IOV VFs on ConnectX-4 or newer <https://support.mellanox.com/s/article/HowTo-Configure-SR-IOV-for-ConnectX-4-ConnectX-5-ConnectX-6-with-KVM-Ethernet>`_.

For information on **QLogic SR-IOV Ethernet cards**, see the
`User's Guide OpenStack Deployment with SR-IOV Configuration <http://www.qlogic.com/solutions/Documents/UsersGuide_OpenStack_SR-IOV.pdf>`_.

For information on **Broadcom NetXtreme Series Ethernet cards**, see the
`Broadcom NetXtreme Product Page <https://www.broadcom.com/products/ethernet-connectivity/network-adapters>`_.

Using SR-IOV interfaces
~~~~~~~~~~~~~~~~~~~~~~~

In order to enable SR-IOV, the following steps are required:

#. Create Virtual Functions (Compute)
#. Configure allow list for PCI devices in nova-compute (Compute)
#. Configure neutron-server (Controller)
#. Configure nova-scheduler (Controller)
#. Enable neutron sriov-agent (Compute)

We recommend using VLAN provider networks for segregation. This way you can
combine instances without SR-IOV ports and instances with SR-IOV ports on a
single network.

.. note::

   Throughout this guide, ``eth3`` is used as the PF and ``physnet2`` is used
   as the provider network configured as a VLAN range. These ports may vary in
   different environments.

Create Virtual Functions (Compute)
----------------------------------

Create the VFs for the network interface that will be used for SR-IOV. We use
``eth3`` as PF, which is also used as the interface for the VLAN provider
network and has access to the private networks of all machines.

.. note::

   The steps detail how to create VFs using Mellanox ConnectX-4 and newer/Intel
   SR-IOV Ethernet cards on an Intel system. Steps may differ for different
   hardware configurations.

#. Ensure SR-IOV and VT-d are enabled in BIOS.

#. Enable IOMMU in Linux by adding ``intel_iommu=on`` to the kernel parameters,
   for example, using GRUB.

#. On each compute node, create the VFs via the PCI SYS interface:

   .. code-block:: console

      # echo '8' > /sys/class/net/eth3/device/sriov_numvfs

   .. note::

      On some PCI devices, observe that when changing the amount of VFs you
      receive the error ``Device or resource busy``. In this case, you must
      first set ``sriov_numvfs`` to ``0``, then set it to your new value.

   .. note::

      A network interface could be used both for PCI passthrough, using the PF,
      and SR-IOV, using the VFs. If the PF is used, the VF number stored in
      the ``sriov_numvfs`` file is lost. If the PF is attached again to the
      operating system, the number of VFs assigned to this interface will be
      zero. To keep the number of VFs always assigned to this interface,
      modify the interfaces configuration file adding an ``ifup`` script
      command.

      On Ubuntu, modify the ``/etc/network/interfaces`` file:

      .. code-block:: ini

         auto eth3
         iface eth3 inet dhcp
         pre-up echo '4' > /sys/class/net/eth3/device/sriov_numvfs

      On RHEL and derivatives, modify the ``/sbin/ifup-local`` file:

      .. code-block:: bash

         #!/bin/sh
         if [[ "$1" == "eth3" ]]
         then
             echo '4' > /sys/class/net/eth3/device/sriov_numvfs
         fi

   .. warning::

      Alternatively, you can create VFs by passing the ``max_vfs`` to the
      kernel module of your network interface. However, the ``max_vfs``
      parameter has been deprecated, so the PCI SYS interface is the preferred
      method.

   You can determine the maximum number of VFs a PF can support:

   .. code-block:: console

      # cat /sys/class/net/eth3/device/sriov_totalvfs
      63

#. Verify that the VFs have been created and are in ``up`` state. For example:

   .. code-block:: console

      # lspci | grep Ethernet
      82:00.0 Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01)
      82:00.1 Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01)
      82:10.0 Ethernet controller: Intel Corporation 82599 Ethernet Controller Virtual Function (rev 01)
      82:10.2 Ethernet controller: Intel Corporation 82599 Ethernet Controller Virtual Function (rev 01)
      82:10.4 Ethernet controller: Intel Corporation 82599 Ethernet Controller Virtual Function (rev 01)
      82:10.6 Ethernet controller: Intel Corporation 82599 Ethernet Controller Virtual Function (rev 01)
      82:11.0 Ethernet controller: Intel Corporation 82599 Ethernet Controller Virtual Function (rev 01)
      82:11.2 Ethernet controller: Intel Corporation 82599 Ethernet Controller Virtual Function (rev 01)
      82:11.4 Ethernet controller: Intel Corporation 82599 Ethernet Controller Virtual Function (rev 01)
      82:11.6 Ethernet controller: Intel Corporation 82599 Ethernet Controller Virtual Function (rev 01)

   .. code-block:: console

      # ip link show eth3
      8: eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT qlen 1000
         link/ether a0:36:9f:8f:3f:b8 brd ff:ff:ff:ff:ff:ff
         vf 0 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 1 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 2 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 3 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 4 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 5 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 6 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 7 MAC 00:00:00:00:00:00, spoof checking on, link-state auto

   If the interfaces are down, set them to ``up`` before launching a guest,
   otherwise the instance will fail to spawn:

   .. code-block:: console

      # ip link set eth3 up

#. Persist created VFs on reboot:

   .. code-block:: console

      # echo "echo '7' > /sys/class/net/eth3/device/sriov_numvfs" >> /etc/rc.local

   .. note::

      The suggested way of making PCI SYS settings persistent is through
      the ``sysfsutils`` tool. However, this is not available by default on
      many major distributions.

Configuring allow list for PCI devices nova-compute (Compute)
-------------------------------------------------------------

#. Configure which PCI devices the ``nova-compute`` service may use. Edit
   the ``nova.conf`` file:

   .. code-block:: ini

      [pci]
      passthrough_whitelist = { "devname": "eth3", "physical_network": "physnet2"}

   This tells the Compute service that all VFs belonging to ``eth3`` are
   allowed to be passed through to instances and belong to the provider network
   ``physnet2``.

   Alternatively the ``[pci] passthrough_whitelist`` parameter also supports
   allowing devices by:

   - PCI address: The address uses the same syntax as in ``lspci`` and an
     asterisk (``*``) can be used to match anything.

     .. code-block:: ini

        [pci]
        passthrough_whitelist = { "address": "[[[[<domain>]:]<bus>]:][<slot>][.[<function>]]", "physical_network": "physnet2" }

     For example, to match any domain, bus ``0a``, slot ``00``, and all
     functions:

     .. code-block:: ini

        [pci]
        passthrough_whitelist = { "address": "*:0a:00.*", "physical_network": "physnet2" }

   - PCI ``vendor_id`` and ``product_id`` as displayed by the Linux utility
     ``lspci``.

     .. code-block:: ini

        [pci]
        passthrough_whitelist = { "vendor_id": "<id>", "product_id": "<id>", "physical_network": "physnet2" }

   If the device defined by the PCI address or ``devname`` corresponds to an
   SR-IOV PF, all VFs under the PF will match the entry. Multiple
   ``[pci] passthrough_whitelist`` entries per host are supported.

   In order to enable SR-IOV to request "trusted mode", the
   ``[pci] passthrough_whitelist`` parameter also supports a ``trusted``
   tag.

   .. note::

      This capability is only supported starting with version 18.0.0
      (Rocky) release of the compute service configured to use the
      libvirt driver.

   .. important::

      There are security implications of enabling trusted ports. The
      trusted VFs can be set into VF promiscuous mode which will
      enable it to receive unmatched and multicast traffic sent to the
      physical function.

   For example, to allow users to request SR-IOV devices with trusted
   capabilities on device ``eth3``:

   .. code-block:: ini

      [pci]
      passthrough_whitelist = { "devname": "eth3", "physical_network": "physnet2", "trusted":"true" }

   The ports will have to be created with a binding profile to match the
   ``trusted`` tag, see `Launching instances with SR-IOV ports`_.

#. Restart the ``nova-compute`` service for the changes to go into effect.

.. _configure_sriov_neutron_server:

Configure neutron-server (Controller)
-------------------------------------

   .. note::

      This section does not apply to remote-managed ports of SmartNIC DPU
      devices which also use SR-IOV at the host side but do not rely on the
      ``sriovnicswitch`` mechanism driver.

#. Add ``sriovnicswitch`` as mechanism driver. Edit the ``ml2_conf.ini`` file
   on each controller:

   .. code-block:: ini

      [ml2]
      mechanism_drivers = openvswitch,sriovnicswitch

#. Ensure your physnet is configured for the chosen network type. Edit the
   ``ml2_conf.ini`` file on each controller:

   .. code-block:: ini

      [ml2_type_vlan]
      network_vlan_ranges = physnet2

#. Add the ``plugin.ini`` file as a parameter to the ``neutron-server``
   service. Edit the appropriate initialization script to configure the
   ``neutron-server`` service to load the plugin configuration file:

   .. code-block:: bash

      --config-file /etc/neutron/neutron.conf
      --config-file /etc/neutron/plugin.ini

#. Restart the ``neutron-server`` service.

Configure nova-scheduler (Controller)
-------------------------------------

#. On every controller node running the ``nova-scheduler`` service, add
   ``PciPassthroughFilter`` to ``[filter_scheduler] enabled_filters`` to enable
   this filter. Ensure ``[filter_scheduler] available_filters`` is set to the
   default of ``nova.scheduler.filters.all_filters``:

   .. code-block:: ini

      [filter_scheduler]
      enabled_filters = ComputeFilter, ComputeCapabilitiesFilter, ImagePropertiesFilter, ServerGroupAntiAffinityFilter, ServerGroupAffinityFilter, PciPassthroughFilter
      available_filters = nova.scheduler.filters.all_filters

#. Restart the ``nova-scheduler`` service.

Enable neutron-sriov-nic-agent (Compute)
----------------------------------------

#. Install the SR-IOV agent, if necessary.

#. Edit the ``sriov_agent.ini`` file on each compute node. For example:

   .. code-block:: ini

      [sriov_nic]
      physical_device_mappings = physnet2:eth3
      exclude_devices =

   .. note::

      The ``physical_device_mappings`` parameter is not limited to be a 1-1
      mapping between physical networks and NICs. This enables you to map the
      same physical network to more than one NIC. For example, if ``physnet2``
      is connected to ``eth3`` and ``eth4``, then
      ``physnet2:eth3,physnet2:eth4`` is a valid option.

   .. note::

      The SR-IOV agent does not implement any kind of firewall driver.

   The ``exclude_devices`` parameter is empty, therefore, all the VFs
   associated with eth3 may be configured by the agent. To exclude specific
   VFs, add them to the ``exclude_devices`` parameter as follows:

   .. code-block:: ini

      exclude_devices = eth1:0000:07:00.2;0000:07:00.3,eth2:0000:05:00.1;0000:05:00.2

#. Ensure the SR-IOV agent runs successfully:

   .. code-block:: console

      # neutron-sriov-nic-agent \
        --config-file /etc/neutron/neutron.conf \
        --config-file /etc/neutron/plugins/ml2/sriov_agent.ini

#. Enable the neutron SR-IOV agent service.

   If installing from source, you must configure a daemon file for the init
   system manually.

(Optional) FDB L2 agent extension
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Forwarding DataBase (FDB) population is an L2 agent extension to OVS agent. Its
objective is to update the FDB table for existing instance
using normal port. This enables communication between SR-IOV instances and
normal instances. The use cases of the FDB population extension are:

* Direct port and normal port instances reside on the same compute node.

* Direct port instance that uses floating IP address and network node
  are located on the same host.

For additional information describing the problem, refer to:
`Virtual switching technologies and Linux bridge.
<https://events.static.linuxfound.org/sites/events/files/slides/LinuxConJapan2014_makita_0.pdf>`_

#. Edit the ``ovs_agent.ini`` file on each compute node. For example:

   .. code-block:: console

      [agent]
      extensions = fdb

#. Add the FDB section and the ``shared_physical_device_mappings`` parameter.
   This parameter maps each physical port to its physical network name. Each
   physical network can be mapped to several ports:

   .. code-block:: console

      [FDB]
      shared_physical_device_mappings = physnet1:p1p1, physnet1:p1p2

Launching instances with SR-IOV ports
-------------------------------------

Once configuration is complete, you can launch instances with SR-IOV ports.

#. If it does not already exist, create a network and subnet for the chosen
   physnet. This is the network to which SR-IOV ports will be attached. For
   example:

   .. code-block:: console

      $ openstack network create --provider-physical-network physnet2 \
          --provider-network-type vlan --provider-segment 1000 \
          sriov-net

      $ openstack subnet create --network sriov-net \
          --subnet-pool shared-default-subnetpool-v4 \
          sriov-subnet

#. Get the ``id`` of the network where you want the SR-IOV port to be created:

   .. code-block:: console

      $ net_id=$(openstack network show sriov-net -c id -f value)

#. Create the SR-IOV port. ``vnic-type=direct`` is used here, but other options
   include ``normal``, ``direct-physical``, and ``macvtap``:

   .. code-block:: console

      $ openstack port create --network $net_id --vnic-type direct \
          sriov-port

   Alternatively, to request that the SR-IOV port accept trusted capabilities,
   the binding profile should be enhanced with the ``trusted`` tag.

   .. code-block:: console

      $ openstack port create --network $net_id --vnic-type direct \
          --binding-profile trusted=true \
          sriov-port

#. Get the ``id`` of the created port:

   .. code-block:: console

      $ port_id=$(openstack port show sriov-port -c id -f value)

#. Create the instance. Specify the SR-IOV port created in step two for the
   NIC:

   .. code-block:: console

      $ openstack server create --flavor m1.large --image ubuntu_18.04 \
          --nic port-id=$port_id \
          test-sriov

   .. note::

      There are two ways to attach VFs to an instance. You can create an SR-IOV
      port or use the ``pci_alias`` in the Compute service. For more
      information about using ``pci_alias``, refer to `nova-api
      configuration`__.

      __ https://docs.openstack.org/nova/latest/admin/pci-passthrough.html#configure-nova-api-controller

SR-IOV with ConnectX-3/ConnectX-3 Pro Dual Port Ethernet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In contrast to Mellanox newer generation NICs, ConnectX-3 family network
adapters expose a single PCI device (PF) in the system regardless of the number
of physical ports. When the device is **dual port** and SR-IOV is enabled and
configured we can observe some inconsistencies in linux networking subsystem.

.. note::
    In the example below ``enp4s0`` represents PF net device associated with physical port 1 and
    ``enp4s0d1`` represents PF net device associated with physical port 2.

**Example:** A system with ConnectX-3 dual port device and a total of four VFs
configured, two VFs assigned to port one and two VFs assigned to port two.

.. code-block:: console

    $ lspci | grep Mellanox
    04:00.0 Network controller: Mellanox Technologies MT27520 Family [ConnectX-3 Pro]
    04:00.1 Network controller: Mellanox Technologies MT27500/MT27520 Family [ConnectX-3/ConnectX-3 Pro Virtual Function]
    04:00.2 Network controller: Mellanox Technologies MT27500/MT27520 Family [ConnectX-3/ConnectX-3 Pro Virtual Function]
    04:00.3 Network controller: Mellanox Technologies MT27500/MT27520 Family [ConnectX-3/ConnectX-3 Pro Virtual Function]
    04:00.4 Network controller: Mellanox Technologies MT27500/MT27520 Family [ConnectX-3/ConnectX-3 Pro Virtual Function]

Four VFs are available in the system, however,

.. code-block:: console

    $ ip link show
    31: enp4s0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop master ovs-system state DOWN mode DEFAULT group default qlen 1000
        link/ether f4:52:14:01:d9:e1 brd ff:ff:ff:ff:ff:ff
        vf 0 MAC 00:00:00:00:00:00, vlan 4095, spoof checking off, link-state auto
        vf 1 MAC 00:00:00:00:00:00, vlan 4095, spoof checking off, link-state auto
        vf 2 MAC 00:00:00:00:00:00, vlan 4095, spoof checking off, link-state auto
        vf 3 MAC 00:00:00:00:00:00, vlan 4095, spoof checking off, link-state auto
    32: enp4s0d1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
        link/ether f4:52:14:01:d9:e2 brd ff:ff:ff:ff:ff:ff
        vf 0 MAC 00:00:00:00:00:00, vlan 4095, spoof checking off, link-state auto
        vf 1 MAC 00:00:00:00:00:00, vlan 4095, spoof checking off, link-state auto
        vf 2 MAC 00:00:00:00:00:00, vlan 4095, spoof checking off, link-state auto
        vf 3 MAC 00:00:00:00:00:00, vlan 4095, spoof checking off, link-state auto

**ip** command identifies each PF associated net device as having four VFs
*each*.

.. note::

     Mellanox ``mlx4`` driver allows *ip* commands to perform configuration of *all*
     VFs from either PF associated network devices.

To allow neutron SR-IOV agent to properly identify the VFs that belong to the
correct PF network device (thus to the correct network port) Admin is required
to provide the ``exclude_devices`` configuration option in ``sriov_agent.ini``

**Step 1**: derive the VF to Port mapping from mlx4 driver configuration file:
``/etc/modprobe.d/mlnx.conf``  or ``/etc/modprobe.d/mlx4.conf``

.. code-block:: console

    $ cat /etc/modprobe.d/mlnx.conf | grep "options mlx4_core"
    options mlx4_core port_type_array=2,2 num_vfs=2,2,0 probe_vf=2,2,0 log_num_mgm_entry_size=-1

Where:

``num_vfs=n1,n2,n3`` - The driver will enable ``n1`` VFs on physical port 1,
``n2`` VFs on physical port 2 and
``n3`` dual port VFs (applies only to dual port HCA when all ports are
Ethernet ports).


``probe_vfs=m1,m2,m3`` - the driver probes ``m1`` single port VFs on
physical port 1,
``m2`` single port VFs on physical port 2 (applies only if such a port exist)
``m3`` dual port VFs. Those VFs are attached to the hypervisor. (applies only
if all ports are configured as Ethernet).

The VFs will be enumerated in the following order:

1. port 1 VFs
2. port 2 VFs
3. dual port VFs

In our example:

| 04:00.0 : PF associated to **both** ports.
| 04:00.1 : VF associated to port **1**
| 04:00.2 : VF associated to port **1**
| 04:00.3 : VF associated to port **2**
| 04:00.4 : VF associated to port **2**

**Step 2:** Update ``exclude_devices`` configuration option in
``sriov_agent.ini`` with the correct mapping

Each PF associated net device shall exclude the **other** port's VFs

.. code-block:: ini

    [sriov_nic]
    physical_device_mappings = physnet1:enp4s0,physnet2:enp4s0d1
    exclude_devices = enp4s0:0000:04:00.3;0000:04:00.4,enp4s0d1:0000:04:00.1;0000:04:00.2

SR-IOV with InfiniBand
~~~~~~~~~~~~~~~~~~~~~~

The support for SR-IOV with InfiniBand allows a Virtual PCI device (VF) to
be directly mapped to the guest, allowing higher performance and advanced
features such as RDMA (remote direct memory access). To use this feature,
you must:

#. Use InfiniBand enabled network adapters.

#. Run InfiniBand subnet managers to enable InfiniBand fabric.

   All InfiniBand networks must have a subnet manager running for the network
   to function. This is true even when doing a simple network of two
   machines with no switch and the cards are plugged in back-to-back. A
   subnet manager is required for the link on the cards to come up.
   It is possible to have more than one subnet manager. In this case, one
   of them will act as the primary, and any other will act as a backup that
   will take over when the primary subnet manager fails.

#. Install the ``ebrctl`` utility on the compute nodes.

   Check that ``ebrctl`` is listed somewhere in ``/etc/nova/rootwrap.d/*``:

   .. code-block:: console

      $ grep 'ebrctl' /etc/nova/rootwrap.d/*

   If ``ebrctl`` does not appear in any of the rootwrap files, add this to the
   ``/etc/nova/rootwrap.d/compute.filters`` file in the ``[Filters]`` section.

   .. code-block:: ini

      [Filters]
      ebrctl: CommandFilter, ebrctl, root

Known limitations
~~~~~~~~~~~~~~~~~

* When using Quality of Service (QoS), ``max_burst_kbps`` (burst over
  ``max_kbps``) is not supported. In addition, ``max_kbps`` is rounded to
  Mbps.
* Security groups are not supported when using SR-IOV.
* SR-IOV is not integrated into the OpenStack Dashboard (horizon). Users must
  use the CLI or API to configure SR-IOV interfaces.
* Live migration support has been added to the Libvirt Nova virt-driver in the
  Train release for instances with neutron SR-IOV ports. Indirect mode SR-IOV
  interfaces (vnic-type: macvtap or virtio-forwarder) can now be migrated
  transparently to the guest. Direct mode SR-IOV interfaces (vnic-type: direct
  or direct-physical) are detached before the migration and reattached after
  the migration so this is not transparent to the guest. To avoid loss of
  network connectivy when live migrating with direct mode sriov the user should
  create a failover bond in the guest with a transparently live migration port
  type e.g. vnic-type normal or indirect mode SR-IOV.

  .. note::

     SR-IOV features may require a specific NIC driver version, depending on the vendor.
     Intel NICs, for example, require ixgbe version 4.4.6 or greater, and ixgbevf version
     3.2.2 or greater.
* Attaching SR-IOV ports to existing servers is supported starting with the
  Victoria release.
