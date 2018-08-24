.. _intro-nat:

===========================
Network address translation
===========================

*Network Address Translation* (NAT) is a process for modifying the source or
destination addresses in the headers of an IP packet while the packet is
in transit. In general, the sender and receiver applications are not aware that
the IP packets are being manipulated.

NAT is often implemented by routers, and so we will refer to the host
performing NAT as a *NAT router*. However, in OpenStack deployments it
is typically Linux servers that implement the NAT functionality, not
hardware routers. These servers use the
`iptables <https://www.netfilter.org/projects/iptables/index.html>`_
software package to implement the NAT functionality.

There are multiple variations of NAT, and here we describe three kinds
commonly found in OpenStack deployments.

SNAT
~~~~

In *Source Network Address Translation* (SNAT), the NAT router modifies the IP
address of the sender in IP packets. SNAT is commonly used to enable
hosts with *private addresses* to communicate with servers on the
public Internet.

`RFC 1918 <https://tools.ietf.org/rfc/rfc1918>`_
reserves the following three subnets as private addresses:

* ``10.0.0.0/8``
* ``172.16.0.0/12``
* ``192.168.0.0/16``

These IP addresses are not publicly routable, meaning that a host on the public
Internet can not send an IP packet to any of these addresses. Private IP
addresses are widely used in both residential and corporate environments.

Often, an application running on a host with a private IP address will need to
connect to a server on the public Internet. An example is a user
who wants to access a public website such as www.openstack.org. If the IP
packets reach the web server at www.openstack.org with a private IP address as
the source, then the web server cannot send packets back to the sender.

SNAT solves this problem by modifying the source IP address to an IP address
that is routable on the public Internet. There are different variations of
SNAT; in the form that OpenStack deployments use, a NAT router on the path
between the sender and receiver replaces the packet's source IP
address with the router's public IP address. The router also modifies
the source TCP or UDP port to another value, and the router maintains
a record of the sender's true IP address and port, as well as the
modified IP address and port.

When the router receives a packet with the matching IP address and port, it
translates these back to the private IP address and port, and forwards the
packet along.

Because the NAT router modifies ports as well as IP addresses, this
form of SNAT is sometimes referred to as *Port Address Translation*
(PAT). It is also sometimes referred to as *NAT overload*.

OpenStack uses SNAT to enable applications running inside of instances to
connect out to the public Internet.

DNAT
~~~~

In *Destination Network Address Translation* (DNAT), the NAT router
modifies the IP address of the destination in IP packet headers.

OpenStack uses DNAT to route packets from instances to the OpenStack
metadata service. Applications running inside of instances access the
OpenStack metadata service by making HTTP GET requests to a web server
with IP address 169.254.169.254. In an OpenStack deployment, there is
no host with this IP address. Instead, OpenStack uses DNAT to change
the destination IP of these packets so they reach the network
interface that a metadata service is listening on.

One-to-one NAT
~~~~~~~~~~~~~~

In *one-to-one NAT*, the NAT router maintains a one-to-one mapping
between private IP addresses and public IP addresses. OpenStack uses
one-to-one NAT to implement floating IP addresses.

