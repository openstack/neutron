.. _ovn_dpdk:

===================
DPDK Support in OVN
===================

Configuration Settings
----------------------

The following configuration parameter needs to be set in the Neutron ML2
plugin configuration file under the 'ovn' section to enable DPDK support.

**vhost_sock_dir**
    This is the directory path in which vswitch daemon in all the compute
    nodes creates the virtio socket. Follow the instructions in
    INSTALL.DPDK.md in openvswitch source tree to know how to configure DPDK
    support in vswitch daemons.

Configuration Settings in compute hosts
---------------------------------------

Compute nodes configured with OVS DPDK should set the datapath_type as
"netdev" for the integration bridge (managed by OVN) and all other bridges if
connected to the integration bridge via patch ports. The below command can be
used to set the datapath_type.

.. code-block:: console

    $ sudo ovs-vsctl set Bridge br-int datapath_type=netdev
