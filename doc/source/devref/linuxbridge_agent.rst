===============================
L2 Networking with Linux Bridge
===============================

This Agent uses the `Linux Bridge
<http://www.linuxfoundation.org/collaborate/workgroups/networking/bridge>`_ to
provide L2 connectivity for VM instances running on the compute node to the
public network.  A graphical illustration of the deployment can be found in
`OpenStack Admin Guide Linux Bridge
<http://docs.openstack.org/admin-guide-cloud/content/under_the_hood_linuxbridge.html>`_

In most common deployments, there is a compute and a network node. On both the
compute and the network node, the Linux Bridge Agent will manage virtual
switches, connectivity among them, and interaction via virtual ports with other
network components such as namespaces and underlying interfaces. Additionally,
on the compute node, the Linux Bridge Agent will manage security groups.

Three use cases and their packet flow are documented as follows:

1. `Legacy implementation with Linux Bridge
   <http://docs.openstack.org/networking-guide/deploy_scenario1b.html>`_

2. `High Availability using L3HA with Linux Bridge
   <http://docs.openstack.org/networking-guide/deploy_scenario3b.html>`_

3. `Provider networks with Linux Bridge
   <http://docs.openstack.org/networking-guide/deploy_scenario4b.html>`_
