.. _deploy-ovs:

=============================
Open vSwitch mechanism driver
=============================

The Open vSwitch (OVS) mechanism driver uses a combination of OVS and Linux
bridges as interconnection devices. However, optionally enabling the OVS
native implementation of security groups removes the dependency on Linux
bridges.

We recommend using Open vSwitch version 2.4 or higher. Optional features
may require a higher minimum version.

.. toctree::
   :maxdepth: 2

   deploy-ovs-provider
   deploy-ovs-selfservice
   deploy-ovs-ha-vrrp
   deploy-ovs-ha-dvr
