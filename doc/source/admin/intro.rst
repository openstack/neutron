.. _intro:

============
Introduction
============

The OpenStack Networking service (neutron)
provides an API that allows users to set up and define network connectivity
and addressing in the cloud. The project code-name for Networking services is
neutron. OpenStack Networking handles the creation and management of a virtual
networking infrastructure, including networks, switches, subnets, and
routers for devices managed by the OpenStack Compute service
(nova). Advanced services such as firewalls or virtual private network (VPN)
can also be used.

OpenStack Networking consists of the neutron-server, a database for
persistent storage, and any number of plug-in agents, which provide
other services such as interfacing with native Linux networking
mechanisms, external devices, or SDN controllers.

OpenStack Networking is entirely standalone and can be deployed to a
dedicated host. If your deployment uses a controller host to run
centralized Compute components, you can deploy the Networking server
to that specific host instead.

OpenStack Networking integrates with various OpenStack
components:

* OpenStack Identity service (keystone) is used for authentication
  and authorization of API requests.

* OpenStack Compute service (nova) is used to plug each virtual
  NIC on the VM into a particular network.

* OpenStack Dashboard (horizon) is used by administrators
  and project users to create and manage network services through a web-based
  graphical interface.

.. note::

   The network address ranges used in this guide are chosen in accordance with
   `RFC 5737 <https://tools.ietf.org/rfc/rfc5737>`_ and
   `RFC 3849 <https://tools.ietf.org/html/rfc3849>`_, and as such are restricted
   to the following:

   **IPv4:**

   * 192.0.2.0/24
   * 198.51.100.0/24
   * 203.0.113.0/24

   **IPv6:**

   * 2001:DB8::/32

   The network address ranges in the examples of this guide should not be used
   for any purpose other than documentation.

.. note::

   To reduce clutter, this guide removes command output without relevance
   to the particular action.

.. toctree::
   :maxdepth: 2

   intro-basic-networking
   intro-network-components
   intro-overlay-protocols
   intro-network-namespaces
   intro-nat
   intro-os-networking
