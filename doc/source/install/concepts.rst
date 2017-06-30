Networking (neutron) concepts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenStack Networking (neutron) manages all networking facets for the
Virtual Networking Infrastructure (VNI) and the access layer aspects
of the Physical Networking Infrastructure (PNI) in your OpenStack
environment. OpenStack Networking enables projects to create advanced
virtual network topologies which may include services such as a
firewall, a load balancer, and a virtual private network (VPN).

Networking provides networks, subnets, and routers as object abstractions.
Each abstraction has functionality that mimics its physical counterpart:
networks contain subnets, and routers route traffic between different
subnets and networks.

Any given Networking set up has at least one external network. Unlike
the other networks, the external network is not merely a virtually
defined network. Instead, it represents a view into a slice of the
physical, external network accessible outside the OpenStack
installation. IP addresses on the external network are accessible by
anybody physically on the outside network.

In addition to external networks, any Networking set up has one or more
internal networks. These software-defined networks connect directly to
the VMs. Only the VMs on any given internal network, or those on subnets
connected through interfaces to a similar router, can access VMs connected
to that network directly.

For the outside network to access VMs, and vice versa, routers between
the networks are needed. Each router has one gateway that is connected
to an external network and one or more interfaces connected to internal
networks. Like a physical router, subnets can access machines on other
subnets that are connected to the same router, and machines can access the
outside network through the gateway for the router.

Additionally, you can allocate IP addresses on external networks to
ports on the internal network. Whenever something is connected to a
subnet, that connection is called a port. You can associate external
network IP addresses with ports to VMs. This way, entities on the
outside network can access VMs.

Networking also supports *security groups*. Security groups enable
administrators to define firewall rules in groups. A VM can belong to
one or more security groups, and Networking applies the rules in those
security groups to block or unblock ports, port ranges, or traffic types
for that VM.

Each plug-in that Networking uses has its own concepts. While not vital
to operating the VNI and OpenStack environment, understanding these
concepts can help you set up Networking. All Networking installations
use a core plug-in and a security group plug-in (or just the No-Op
security group plug-in). Additionally, Firewall-as-a-Service (FWaaS) and
Load-Balancer-as-a-Service (LBaaS) plug-ins are available.
