.. _ovn_baremetal:

====================================
Baremetal provisioning guide for OVN
====================================

The purpose of this page is to describe how the baremetal provisioning
can be configured with ML2/OVN.

Currently, baremetal provisioning with ML2/OVN can be achieved using
the OVN's built-in DHCP server for IPv4 or using Neutron's DHCP agent
for either IPv4 or IPv6.

How to configure it
-------------------

Scheduling baremetal ports
~~~~~~~~~~~~~~~~~~~~~~~~~~

The first thing to know is that when a port with VNIC ``baremetal`` is
created, ML2/OVN will create an OVN port of the type ``external``. These
ports will be bound to nodes that have external connectivity and are
responsible to responding to the ARP requests on behalf of the baremetal
node.

For more information about external ports, its scheduling and
troubleshoot please check the :ref:`External Ports guide
<ovn_external_ports>`.

Metadata access
~~~~~~~~~~~~~~~

Different from ML2/OVS, ML2/OVN requires to have the
``ovn-metadata-agent`` running on the node that the virtual machines
are running onto. Since baremetal requires an external port that will
be bound to another node, as explained `Scheduling baremetal ports`_
section, it is required that the ``ovn-metadata-agent`` is also deployed
on the nodes marked with the ``enable-chassis-as-gw`` option so it can
serve metadata to the baremetal nodes booting off those external ports.

Using OVN built-in DHCP for PXE booting
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Currently, only IPv4 is supported for PXE booting a baremetal node using
the OVN's built-in DHCP server. It's also required to have OVN running
the version **22.06** or above.

The version of OVN used for baremetal provisioning should include the
following commits [[#]_] [[#]_].

And last, make sure that configuration option
``[ovn]/disable_ovn_dhcp_for_baremetal_ports`` is set to **False**
(the default).

Using Neutron DHCP Agent for PXE booting
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If using the OVN built-in DHCP server is not desirable or if
PXE booting nodes off IPv6 is required, the operator will need
to deploy Neutron's DHCP agents on the controller nodes and also
disable the OVN's DHCP server for the baremetal ports by setting the
``[ovn]/disable_ovn_dhcp_for_baremetal_ports`` configuration option to
**True** (defaults to False).

.. [#] https://github.com/ovn-org/ovn/commit/0057cde2a64749bd2dbbaff525f7a1edccbd9c8a
.. [#] https://github.com/ovn-org/ovn/commit/9cbd79c9ebbd0b6d0ea08c2cc70e234e56bb0415
