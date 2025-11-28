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


North/South routing
~~~~~~~~~~~~~~~~~~~

A network with an external port (SR-IOV, baremetal), will create a
``HA_Chassis_Group`` register to schedule these external ports in gateway
chassis. The routers (still) use a set of ``Gateway_Chassis`` registers to
execute the scheduling of the gateway port. Now, since the implementation of
[1]_, when a network is connected as an internal network, the Neutron API will
sync the network ``HA_Chassis_Group`` with the gateway port ``Gateway_Chassis``
set. That will make both scheduling methods to be in sync and will collocate
the gateway router port and the external port in the same OVN gateway chassis;
that allows OVN to route the traffic from the external port through the gateway
port.

When the network ``HA_Chassis_Group`` is updated, it could be possible that
the currently assigned gateway chassis changes. However, before connecting the
network to the router, this port is used only for DHCP and metadata; the
external port binding change won't interrupt the traffic.


References
~~~~~~~~~~

.. [1] https://review.opendev.org/q/topic:%22bug/2125553%22
