.. _config-ovs-offload:

================================
Open vSwitch hardware offloading
================================

The purpose of this page is to describe how to enable Open vSwitch hardware
offloading functionality available in OpenStack (using OpenStack Networking).
This functionality was first introduced in the OpenStack Pike release.
This page intends to serve as a guide for how to configure OpenStack Networking
and OpenStack Compute to enable Open vSwitch hardware offloading.

The basics
~~~~~~~~~~

Open vSwitch is a production quality, multilayer virtual switch licensed under
the open source Apache 2.0 license.  It is designed to enable massive network
automation through programmatic extension, while still supporting standard
management interfaces and protocols. Open vSwitch (OVS) allows Virtual Machines
(VM) to communicate with each other and with the outside world.
The OVS software based solution is CPU intensive, affecting system performance
and preventing fully utilizing available bandwidth.

.. list-table::
   :header-rows: 1
   :widths: 30 90

   * - Term
     - Definition
   * - PF
     - Physical Function. The physical Ethernet controller that supports
       SR-IOV.
   * - VF
     - Virtual Function. The virtual PCIe device created from a physical
       Ethernet controller.
   * - Representor Port
     - Virtual network interface similar to SR-IOV port that represents
       Nova instance.
   * - First Compute Node
     - OpenStack Compute Node that can host Compute instances (Virtual Machines).
   * - Second Compute Node
     - OpenStack Compute Node that can host Compute instances (Virtual Machines).


Supported Ethernet controllers
------------------------------

The following manufacturers are known to work:

- Mellanox ConnectX-4 NIC (VLAN Offload)
- Mellanox ConnectX-4 Lx/ConnectX-5 NICs (VLAN/VXLAN Offload)
- Broadcom NetXtreme-S series NICs
- Broadcom NetXtreme-E series NICs

For information on **Mellanox Ethernet Cards**, see
`Mellanox: Ethernet Cards - Overview
<http://www.mellanox.com/page/ethernet_cards_overview>`_.

Prerequisites
-------------

- Linux Kernel >= 4.13
- Open vSwitch >= 2.8
- iproute >= 4.12
- Mellanox or Broadcom NIC

    .. note:: Mellanox NIC FW that supports Open vSwitch hardware offloading:

       ConnectX-5    >= 16.21.0338

       ConnectX-4    >= 12.18.2000

       ConnectX-4 Lx >= 14.21.0338

Using Open vSwitch hardware offloading
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to enable Open vSwitch hardware offloading, the following steps are required:

#. Enable SR-IOV
#. Configure NIC to switchdev mode (relevant Nodes)
#. Enable Open vSwitch hardware offloading

.. note::

   Throughout this guide, ``enp3s0f0`` is used as the PF and ``eth3`` is used
   as the representor port. These ports may vary in different environments.

.. note::

   Throughout this guide, we use ``systemctl`` to restart OpenStack services.
   This is correct for ``systemd`` OS. Other methods to restart services should be
   used in other environments.

Create Compute virtual functions
----------------------------------

Create the VFs for the network interface that will be used for SR-IOV. We use
``enp3s0f0`` as PF, which is also used as the interface for the VLAN provider
network and has access to the private networks of all nodes.

.. note::

   The following steps detail how to create VFs using Mellanox ConnectX-4 and
   SR-IOV Ethernet cards on an Intel system. Steps may be different for the
   hardware of your choice.

#. Ensure SR-IOV and VT-d are enabled on the system.
   Enable IOMMU in Linux by adding ``intel_iommu=on`` to kernel parameters,
   for example, using GRUB.

#. On each Compute node, create the VFs:

   .. code-block:: bash

      # echo '4' > /sys/class/net/enp3s0f0/device/sriov_numvfs

   .. note::

      A network interface can be used both for PCI passthrough, using the PF,
      and SR-IOV, using the VFs. If the PF is used, the VF number stored in
      the ``sriov_numvfs`` file is lost. If the PF is attached again to the
      operating system, the number of VFs assigned to this interface will be
      zero. To keep the number of VFs always assigned to this interface,
      update a relevant file according to your OS.
      See some examples below:

      In Ubuntu, modifying the ``/etc/network/interfaces`` file:

      .. code-block:: ini

         auto enp3s0f0
         iface enp3s0f0 inet dhcp
         pre-up echo '4' > /sys/class/net/enp3s0f0/device/sriov_numvfs


      In Red Hat, modifying the ``/sbin/ifup-local`` file:

      .. code-block:: bash

         #!/bin/sh
         if [[ "$1" == "enp3s0f0" ]]
         then
             echo '4' > /sys/class/net/enp3s0f0/device/sriov_numvfs
         fi


   .. warning::

      Alternatively, you can create VFs by passing the ``max_vfs`` to the
      kernel module of your network interface. However, the ``max_vfs``
      parameter has been deprecated, so the PCI /sys interface is the preferred
      method.

   You can determine the maximum number of VFs a PF can support:

   .. code-block:: bash

      # cat /sys/class/net/enp3s0f0/device/sriov_totalvfs
      8

#. Verify that the VFs have been created and are in ``up`` state:

   .. note::

      The PCI bus number of the PF (03:00.0) and VFs (03:00.2 .. 03:00.5)
      will be used later.

   .. code-block::bash

      # lspci | grep Ethernet
      03:00.0 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5]
      03:00.1 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5]
      03:00.2 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5 Virtual Function]
      03:00.3 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5 Virtual Function]
      03:00.4 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5 Virtual Function]
      03:00.5 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5 Virtual Function]


   .. code-block:: bash

      # ip link show enp3s0f0
      8: enp3s0f0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT qlen 1000
         link/ether a0:36:9f:8f:3f:b8 brd ff:ff:ff:ff:ff:ff
         vf 0 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 1 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 2 MAC 00:00:00:00:00:00, spoof checking on, link-state auto
         vf 3 MAC 00:00:00:00:00:00, spoof checking on, link-state auto

   If the interfaces are down, set them to ``up`` before launching a guest,
   otherwise the instance will fail to spawn:

   .. code-block:: bash

      # ip link set enp3s0f0 up


Configure Open vSwitch hardware offloading
------------------------------------------

#. Change the e-switch mode from legacy to switchdev on the PF device.
   This will also create the VF representor network devices in the host OS.

   .. code-block:: bash

      # echo 0000:03:00.2 > /sys/bus/pci/drivers/mlx5_core/unbind

   This tells the driver to unbind VF 03:00.2

   .. note::

     This should be done for all relevant VFs
     (in this example 0000:03:00.2 .. 0000:03:00.5)

#. Enable Open vSwitch hardware offloading,
   set PF to switchdev mode and bind VFs back.

   .. code-block:: bash

     # sudo devlink dev eswitch set pci/0000:03:00.0 mode switchdev
     # sudo ethtool -K enp3s0f0 hw-tc-offload on
     # echo 0000:03:00.2 > /sys/bus/pci/drivers/mlx5_core/bind

   .. note::

     This should be done for all relevant VFs
     (in this example 0000:03:00.2 .. 0000:03:00.5)

#. Restart Open vSwitch

   .. code-block:: bash

      # sudo systemctl enable openvswitch.service
      # sudo ovs-vsctl set Open_vSwitch . other_config:hw-offload=true
      # sudo systemctl restart openvswitch.service

   .. note::

      The given aging of OVS is given in milliseconds and can be controlled with:

   .. code-block:: bash

      # ovs-vsctl set Open_vSwitch . other_config:max-idle=30000


Configure Nodes (VLAN Configuration)
-------------------------------------

#. Update ``/etc/neutron/plugins/ml2/ml2_conf.ini`` on Controller nodes

   .. code-block:: ini

      [ml2]
      tenant_network_types = vlan
      type_drivers = vlan
      mechanism_drivers = openvswitch

   .. end

#. Update ``/etc/neutron/neutron.conf`` on Controller nodes

   .. code-block:: ini

      [DEFAULT]
      core_plugin = ml2

   .. end

#. Update ``/etc/nova/nova.conf`` on Controller nodes

   .. code-block:: ini

      [filter_scheduler]
      enabled_filters = PciPassthroughFilter

   .. end

#. Update ``/etc/nova/nova.conf`` on Compute nodes

   .. code-block:: ini

      [pci]
      #VLAN Configuration passthrough_whitelist example
      passthrough_whitelist ={"'"address"'":"'"*:'"03:00"'.*"'","'"physical_network"'":"'"physnet2"'"}

   .. end


Configure Nodes (VXLAN Configuration)
-------------------------------------


#. Update ``/etc/neutron/plugins/ml2/ml2_conf.ini`` on Controller nodes

   .. code-block:: ini

      [ml2]
      tenant_network_types = vxlan
      type_drivers = vxlan
      mechanism_drivers = openvswitch

   .. end

#. Update ``/etc/neutron/neutron.conf`` on Controller nodes

   .. code-block:: ini

      [DEFAULT]
      core_plugin = ml2

   .. end

#. Update ``/etc/nova/nova.conf`` on Controller nodes

   .. code-block:: ini

      [filter_scheduler]
      enabled_filters = PciPassthroughFilter

   .. end

#. Update ``/etc/nova/nova.conf`` on Compute nodes

   .. note::

      VXLAN configuration requires physical_network to be null.

   .. code-block:: ini

      [pci]
      #VLAN Configuration passthrough_whitelist example
      passthrough_whitelist ={"'"address"'":"'"*:'"03:00"'.*"'","'"physical_network"'":null}

   .. end

#. Restart nova and neutron services

   .. code-block:: bash

     # sudo systemctl restart openstack-nova-compute.service
     # sudo systemctl restart openstack-nova-scheduler.service
     # sudo systemctl restart neutron-server.service


Validate Open vSwitch hardware offloading
-----------------------------------------

   .. note::

     In this example we will bring up two instances on different Compute nodes and
     send ICMP echo packets between them. Then we will check TCP packets on
     a representor port and we will see that only the first packet will be
     shown there. All the rest will be offloaded.

#. Create a port ``direct`` on ``private`` network

   .. code-block:: bash

      # openstack port create --network private --vnic-type=direct --binding-profile '{"capabilities": ["switchdev"]}' direct_port1


#. Create an instance using the direct port on 'First Compute Node'

   .. code-block:: bash

      # openstack server create --flavor m1.small --image mellanox_fedora --nic port-id=direct_port1 vm1


   .. note::

      In this example, we used Mellanox Image with NIC Drivers that can be downloaded from
      http://www.mellanox.com/repository/solutions/openstack/images/mellanox_eth.img


#. Repeat steps above and create a second instance on 'Second Compute Node'

   .. code-block:: bash

      # openstack port create --network private --vnic-type=direct --binding-profile '{"capabilities": ["switchdev"]}' direct_port2
      # openstack server create --flavor m1.small --image mellanox_fedora --nic port-id=direct_port2 vm2

   .. note::

      You can use  --availability-zone nova:compute_node_1 option
      to set the desired Compute Node


#. Connect to instance1 and send ICMP Echo Request packets to instance2

   .. code-block:: bash

      # vncviewer localhost:5900
      vm_1# ping vm2

#. Connect to 'Second Compute Node' and find representor port of the instance

   .. note::

      Find a representor port first, in our case it's eth3

   .. code-block:: console

      compute_node2# ip link show enp3s0f0
      6: enp3s0f0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq master ovs-system state UP mode DEFAULT group default qlen 1000
         link/ether ec:0d:9a:46:9e:84 brd ff:ff:ff:ff:ff:ff
         vf 0 MAC 00:00:00:00:00:00, spoof checking off, link-state enable, trust off, query_rss off
         vf 1 MAC 00:00:00:00:00:00, spoof checking off, link-state enable, trust off, query_rss off
         vf 2 MAC 00:00:00:00:00:00, spoof checking off, link-state enable, trust off, query_rss off
         vf 3 MAC fa:16:3e:b9:b8:ce, vlan 57, spoof checking on, link-state enable, trust off, query_rss off

      compute_node2# ls -l /sys/class/net/
      lrwxrwxrwx 1 root root 0 Sep 11 10:54 eth0 -> ../../devices/virtual/net/eth0
      lrwxrwxrwx 1 root root 0 Sep 11 10:54 eth1 -> ../../devices/virtual/net/eth1
      lrwxrwxrwx 1 root root 0 Sep 11 10:54 eth2 -> ../../devices/virtual/net/eth2
      lrwxrwxrwx 1 root root 0 Sep 11 10:54 eth3 -> ../../devices/virtual/net/eth3

      compute_node2# sudo ovs-dpctl show
      system@ovs-system:
        lookups: hit:1684 missed:1465 lost:0
        flows: 0
        masks: hit:8420 total:1 hit/pkt:2.67
        port 0: ovs-system (internal)
        port 1: br-enp3s0f0 (internal)
        port 2: br-int (internal)
        port 3: br-ex (internal)
        port 4: enp3s0f0
        port 5: tapfdc744bb-61 (internal)
        port 6: qr-a7b1e843-4f (internal)
        port 7: qg-79a77e6d-8f (internal)
        port 8: qr-f55e4c5f-f3 (internal)
        port 9: eth3

   .. end

#. Check traffic on the representor port. Verify that only the first ICMP packet appears.

   .. code-block:: console

      compute_node2# tcpdump -nnn -i eth3

      tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
      listening on eth3, link-type EN10MB (Ethernet), capture size 262144 bytes
      17:12:41.220447 ARP, Request who-has 172.0.0.10 tell 172.0.0.13, length 46
      17:12:41.220684 ARP, Reply 172.0.0.10 is-at fa:16:3e:f2:8b:23, length 42
      17:12:41.260487 IP 172.0.0.13 > 172.0.0.10: ICMP echo request, id 1263, seq 1, length 64
      17:12:41.260778 IP 172.0.0.10 > 172.0.0.13: ICMP echo reply, id 1263, seq 1, length 64
      17:12:46.268951 ARP, Request who-has 172.0.0.13 tell 172.0.0.10, length 42
      17:12:46.271771 ARP, Reply 172.0.0.13 is-at fa:16:3e:1a:10:05, length 46
      17:12:55.354737 IP6 fe80::f816:3eff:fe29:8118 > ff02::1: ICMP6, router advertisement, length 64
      17:12:56.106705 IP 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 62:21:f0:89:40:73, length 300

   .. end
