.. _deploy:

===================
Deployment examples
===================

The following deployment examples provide building blocks of increasing
architectural complexity using the Networking service reference architecture
which implements the Modular Layer 2 (ML2) plug-in with the Open
vSwitch (OVS) mechanism driver. The mechanism driver supports
basic features such as provider networks, self-service networks,
and routers. However, more complex features often require a particular
mechanism driver. Thus, you should consider the requirements (or goals) of
your cloud before choosing a mechanism driver.

After choosing a :ref:`mechanism driver <deploy-mechanism-drivers>`, the
deployment examples generally include the following building blocks:

#. Provider (public/external) networks using IPv4 and IPv6

#. Self-service (project/private/internal) networks including routers using
   IPv4 and IPv6

#. High-availability features

#. Other features such as BGP dynamic routing

Prerequisites
~~~~~~~~~~~~~

Prerequisites, typically hardware requirements, generally increase with each
building block. Each building block depends on proper deployment and operation
of prior building blocks. For example, the first building block (provider
networks) only requires one controller and two compute nodes, the second
building block (self-service networks) adds a network node, and the
high-availability building blocks typically add a second network node for a
total of five nodes. Each building block could also require additional
infrastructure or changes to existing infrastructure such as networks.

For basic configuration of prerequisites, see the latest
`Install Tutorials and Guides <../install/>`__.

.. note::

   Example commands using the ``openstack`` client assume version 3.2.0 or
   higher.

Nodes
-----

The deployment examples refer one or more of the following nodes:

* Controller: Contains control plane components of OpenStack services
  and their dependencies.

  * Two network interfaces: management and provider.
  * Operational SQL server with databases necessary for each OpenStack
    service.
  * Operational message queue service.
  * Operational OpenStack Identity (keystone) service.
  * Operational OpenStack Image Service (glance).
  * Operational management components of the OpenStack Compute (nova) service
    with appropriate configuration to use the Networking service.
  * OpenStack Networking (neutron) server service and ML2 plug-in.

* Network: Contains the OpenStack Networking service layer-3 (routing)
  component. High availability options may include additional components.

  * Three network interfaces: management, overlay, and provider.
  * OpenStack Networking layer-2 (switching) agent, layer-3 agent, and any
    dependencies.

* Compute: Contains the hypervisor component of the OpenStack Compute service
  and the OpenStack Networking layer-2, DHCP, and metadata components.
  High-availability options may include additional components.

  * Two network interfaces: management and provider.
  * Operational hypervisor components of the OpenStack Compute (nova) service
    with appropriate configuration to use the Networking service.
  * OpenStack Networking layer-2 agent, DHCP agent, metadata agent, and any
    dependencies.

Each building block defines the quantity and types of nodes including the
components on each node.

.. note::

   You can virtualize these nodes for demonstration, training, or
   proof-of-concept purposes. However, you must use physical hosts for
   evaluation of performance or scaling.

Networks and network interfaces
-------------------------------

The deployment examples refer to one or more of the following networks
and network interfaces:

* Management: Handles API requests from clients and control plane traffic for
  OpenStack services including their dependencies.
* Overlay: Handles self-service networks using an overlay protocol such as
  VXLAN or GRE.
* Provider: Connects virtual and physical networks at layer-2. Typically
  uses physical network infrastructure for switching/routing traffic to
  external networks such as the Internet.

.. note::

   For best performance, 10+ Gbps physical network infrastructure should
   support jumbo frames.

For illustration purposes, the configuration examples typically reference
the following IP address ranges:

* Provider network 1:

  * IPv4: 203.0.113.0/24
  * IPv6: fd00:203:0:113::/64

* Provider network 2:

  * IPv4: 192.0.2.0/24
  * IPv6: fd00:192:0:2::/64

* Self-service networks:

  * IPv4: 198.51.100.0/24 in /24 segments
  * IPv6: fd00:198:51::/48 in /64 segments

You may change them to work with your particular network infrastructure.

.. _deploy-mechanism-drivers:

Mechanism drivers
~~~~~~~~~~~~~~~~~

.. toctree::
   :maxdepth: 1

   deploy-ovs
