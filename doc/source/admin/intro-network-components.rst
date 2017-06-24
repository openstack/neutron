.. _intro-network-components:

==================
Network components
==================

Switches
~~~~~~~~

Switches are Multi-Input Multi-Output (MIMO) devices that enable packets
to travel from one node to another. Switches connect hosts that belong
to the same layer-2 network. Switches enable forwarding of the
packet received on one port (input) to another port (output) so that they
reach the desired destination node. Switches operate at layer-2 in the
networking model. They forward the traffic based on the destination
Ethernet address in the packet header.

Routers
~~~~~~~

Routers are special devices that enable packets to travel from one
layer-3 network to another. Routers enable communication between two nodes
on different layer-3 networks that are not directly connected to each other.
Routers operate at layer-3 in the networking model. They route the traffic
based on the destination IP address in the packet header.

Firewalls
~~~~~~~~~

Firewalls are used to regulate traffic to and from a host or a network.
A firewall can be either a specialized device connecting two networks or
a software-based filtering mechanism implemented on an operating system.
Firewalls are used to restrict traffic to a host based on the rules
defined on the host. They can filter packets based on several criteria such as
source IP address, destination IP address, port numbers, connection state,
and so on. It is primarily used to protect the hosts from unauthorized access
and malicious attacks. Linux-based operating systems implement firewalls
through ``iptables``.

Load balancers
~~~~~~~~~~~~~~

Load balancers can be software-based or hardware-based devices that allow
traffic to evenly be distributed across several servers. By distributing the
traffic across multiple servers, it avoids overload of a single server thereby
preventing a single point of failure in the product. This further improves the
performance, network throughput, and response time of the servers.
Load balancers are typically used in a 3-tier architecture. In this model,
a load balancer receives a request from the front-end web server,
which then forwards the request to one of the available back-end database
servers for processing. The response from the database server is passed back to
the web server for further processing.
