.. _ovn_sriov:

====================
SR-IOV guide for OVN
====================

The purpose of this page is to describe how SR-IOV works with OVN. Prior
to reading this document, it is recommended to first read :ref:`the
basic guide for SR-IOV<config-sriov>`.

External ports
~~~~~~~~~~~~~~

The SR-IOV feature is leverage by OVN ``external`` ports. For more
information about external ports, its scheduling and troubleshoot,
please check the :ref:`External Ports guide <ovn_external_ports>`.

Environment setup for OVN SR-IOV
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are a very few differences between setting up an environment for
SR-IOV for the OVS and OVN Neutron drivers. As mentioned at the beginning
of this document, the instructions from the :ref:`the basic guide for
SR-IOV<config-sriov>` are required for getting SR-IOV working with the
OVN driver.

The only differences required for an OVN deployment are:

* When configuring the ``mechanism_drivers`` in the *ml2_conf.ini* file
  we should specify ``ovn`` driver instead of the ``openvswitch`` driver
* Disabling the Neutron DHCP agent
* Deploying the OVN Metadata agent on the gateway nodes (controller
  or networker nodes)


Known limitations
~~~~~~~~~~~~~~~~~

The current SR-IOV implementation for the OVN Neutron driver has a few
known limitations that should be addressed in the future:

#. Routing on VLAN tenant network will not work with SR-IOV. This
   is because the external ports are not being co-located with
   the logical router's gateway ports, for more information take a look at
   `bug #1875852 <https://bugs.launchpad.net/neutron/+bug/1875852>`_.
