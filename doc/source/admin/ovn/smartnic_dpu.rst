.. _smartnic_dpu:

===============================
Off-path SmartNIC DPUs with OVN
===============================

The purpose of this page is to describe how off-path SmartNIC DPU hardware
can be integrated with Neutron when OVN mechanism driver is used. For an
in-depth discussion of underlying mechanisms it is recommended to get
familiar with the following specifications

* Neutron `Off-path SmartNIC DPU Port Binding with OVN specification`_;

* `Nova Integration With Off-path Network Backends specification`_.

Overview
--------

A class of devices collectively referred to as off-path SmartNIC DPUs
introduces an important change to earlier architectures where compute and
networking agents used to coexist at the hypervisor host: networking control
plane components are now moved to the SmartNIC DPU's CPU side which includes
``ovs-vswitchd`` and ``ovn-controller``. The following diagram provides an
overview of the components involved::

                           ┌────────────────────────────────────┐
                           │  Hypervisor                        │    LoM Ports
                           │  ┌───────────┐       ┌───────────┐ │   (on-board,
                           │  │ Instance  │       │  Nova     │ ├──┐ optional)
                           │  │(e.g. QEMU)│       │ Compute   │ │  ├─────────┐
                           │  │           │       │           │ ├──┘         │
                           │  └───────────┘       └───────────┘ │            │
                           │                                    │            │
                           └────────────────┬─┬───────┬─┬──┬────┘            │
                                            │ │       │ │  │                 │
                                            │ │       │ │  │ Control Traffic │
                               Instance VF  │ │       │ │  │ PF associated   │
                                            │ │       │ │  │ with an uplink  │
                                            │ │       │ │  │ port or a VF.   │
                                            │ │       │ │  │ (used to replace│
                                            │ │       │ │  │  LoM)           │
       ┌────────────────────────────────────┼─┼───────┼─┼──┼─┐               │
       │   SmartNIC DPU Board               │ │       │ │  │ │               │
       │                                    │ │       │ │  │ │               │
       │  ┌──────────────┐ Control traffic  │ │       │ │  │ │               │
       │  │   App. CPU   │ via PFs or VFs  ┌┴─┴───────┴─┴┐ │ │               │
       │  ├──────────────┤  (DC Fabric)    │             │ │ │               │
       │  │ovn-controller├─────────────────┼─┐           │ │ │               │
       │  ├──────────────┤                 │ │           │ │ │               │
       │  │ovs-vswitchd  │                 │ │NIC Switch │ │ │               │
       │  ├──────────────┤                 │ │ASIC/FPGA  │ │ │               │
       │  │ Neutron OVN  │                 │ │           │ │ │               │
       │  │metadata agent│                 │ │           │ │ │               │
       │  ├──────────────┤Port representors│ │           │ │ │               │
       │  │    br-int    ├═════════════════┤ │           │ │ │               │
       │  └──────────────┘                 └─┼───┬─┬─────┘ │ │               │
     ┌ ┴─ ─ ─ ┐Optional port for             │   │ │       │ │               │
    ─┤OOB Port initial NIC switch config     │   │ │uplink │ │               │
     └ ┬─ ─ ─ ┘                              │   │ │       │ │               │
       │                                     │   │ │       │ │               │
       └─────────────────────────────────────┼───┼─┼───────┼─┘               │
                                             │   │ │       │                 │
                                          ┌──┼───┴─┴───────┼────────┐        │
                                          │  │             │        │        │
                                          │  │   DC Fabric ├────────┼────────┘
                                          │  │             │        │
                                          └──┼─────────────┼────────┘
                                             │             │
                                             │         ┌───┴──────┐
                                             │         │          │
                                         ┌───▼──┐  ┌───▼───┐ ┌────▼────┐
                                         │OVN SB│  │Neutron│ │Placement│
                                         └──────┘  │Server │ │         │
                                                   └───────┘ └─────────┘

Prerequisites
-------------

* OpenStack Yoga or newer;

* `Open vSwitch`_ >= 2.17;

* `Open Virtual Network`_ >= 21.12.0;

* `OVN VIF`_ >= 21.12.0;

* A SmartNIC DPU with the following characteristics:

  * A NIC that exposes a card serial number via a PCIe VPD capability on its
    physical or virtual function PCIe endpoints to both the hypervisor host
    and the DPU host;

  * Exposes the information about representor ports to applications running on
    the SmartNIC DPU's CPU in a manner supported by one of the `OVN VIF Plug
    Providers`_.

Nova configuration
------------------

Hypervisor hosts need to be configured to enable:

* `Nova PCI passthrough`_ for Nova Compute;

  .. important::

    For more information on other version requirements and limitations check
    the `SR-IOV section of the Nova networking guide`_.

* SR-IOV virtual functions on selected physical functions provided by DPUs
  to the hypervisor hosts.

In addition to the regular PCI device allow list configuration, the PCI device
specification must include the ``remote_managed`` tag as in the following
examples:

* Virtual networks without physical segments;

  .. code-block:: ini

     [pci]
     passthrough_whitelist = {"vendor_id": "15b3", "product_id": "101e", "physical_network": null, "remote_managed": "true"}

* Physical networks (flat, VLAN) with a label:

  .. code-block:: ini

     [pci]
     passthrough_whitelist = {"vendor_id": "15b3", "product_id": "101e", "physical_network": "dcfabric", "remote_managed": "true"}

   .. note::

   "dcfabric" is an arbitrary physnet name. In order for this to work it must
   be specified consistenly in Nova config, during OVN configuraton when
   specifying ``external_ids:ovn-bridge-mappings`` and during Neutron provider
   network segment creation.

Auto-Discovery
--------------

When an instance with a ``remote-managed`` port is scheduled to a compute host
with a free remote-managed device, it claims it and supplies additional
information from that device about the NIC to Neutron so that it knows which
OVN chassis needs to handle an representor interface plugging and flow
programming. For PCI VFs this additional information includes:

* A card serial number from the NIC's VPD;

* PF mac address;

* VF logical number.

Neutron uses the card serial number to look up a chassis host name which is
needed for port binding to succeed and the rest is used by ``ovn-vif`` to set
up the matching representor port.

As a result, no direct communication or configuration is required between the
SmartNIC DPU host and the compute host in order to handle matching of compute
hosts to SmartNIC DPUs.

.. note::

   Multiple DPUs per hypervisor host are possible to use, however, at the time
   of writing, there is no way to indicate to Nova which VFs to choose via
   Neutron port object attributes.

Having the OVN controller expose the SmartNIC DPU serial number is accomplished
by providing the serial number via the ``ovn-cms-options`` entry in
*external_ids* column of the SmartNIC DPU local *Open_vSwitch* table:

.. code-block:: bash

   $ ovs-vsctl set Open_vSwitch . external-ids:ovn-cms-options="card-serial-number=AB0123XX0042"

Launch an instance with remote managed port
-------------------------------------------

.. code-block:: bash

   $ openstack port create \
       --network network \
       --vnic-type remote-managed \
       port1

.. code-block:: bash

   $ openstack server create \
       --flavor 1 \
       --nic port-id=port1


.. LINKS
.. _Off-path SmartNIC DPU Port Binding with OVN specification:
   https://specs.openstack.org/openstack/neutron-specs/specs/yoga/off-path-smartnic-dpu-port-binding-with-ovn.html
.. _Nova Integration With Off-path Network Backends specification:
   https://specs.openstack.org/openstack/nova-specs/specs/yoga/approved/integration-with-off-path-network-backends.html
.. _Nova PCI passthrough:
   https://docs.openstack.org/nova/latest/admin/pci-passthrough.html
.. _SR-IOV section of the Nova networking guide:
   https://docs.openstack.org/nova/latest/admin/networking.html#sr-iov
.. _Open vSwitch: https://www.openvswitch.org/
.. _Open Virtual Network: https://www.ovn.org/
.. _OVN VIF: https://github.com/ovn-org/ovn-vif
.. _OVN VIF Plug Providers:
   https://github.com/ovn-org/ovn-vif/tree/main/Documentation/topics/
   vif-plug-providers
