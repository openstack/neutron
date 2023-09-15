Address Scopes and Subnet Pools
===============================

This page discusses subnet pools and address scopes

Subnet Pools
------------

Learn about subnet pools by watching the summit talk given in Vancouver [#]_.

.. [#] http://www.youtube.com/watch?v=QqP8yBUUXBM&t=6m12s

Subnet pools were added in Kilo.  They are relatively simple.  A SubnetPool has
any number of SubnetPoolPrefix objects associated to it.  These prefixes are in
CIDR format.  Each CIDR is a piece of the address space that is available for
allocation.

Subnet Pools support IPv6 just as well as IPv4.

The Subnet model object now has a subnetpool_id attribute whose default is null
for backward compatibility.  The subnetpool_id attribute stores the UUID of the
subnet pool that acted as the source for the address range of a particular
subnet.

When creating a subnet, the subnetpool_id can be optionally specified.  If it
is, the 'cidr' field is not required.  If 'cidr' is specified, it will be
allocated from the pool assuming the pool includes it and hasn't already
allocated any part of it.  If 'cidr' is left out, then the prefixlen attribute
can be specified.  If it is not, the default prefix length will be taken from
the subnet pool.  Think of it this way, the allocation logic always needs to
know the size of the subnet desired.  It can pull it from a specific CIDR,
prefixlen, or default.  A specific CIDR is optional and the allocation will try
to honor it if provided.  The request will fail if it can't honor it.

Subnet pools do not allow overlap of subnets.

Subnet Pool Quotas
~~~~~~~~~~~~~~~~~~

A quota mechanism was provided for subnet pools.  It is different than other
quota mechanisms in Neutron because it doesn't count instances of first class
objects.  Instead it counts how much of the address space is used.

For IPv4, it made reasonable sense to count quota in terms of individual
addresses.  So, if you're allowed exactly one /24, your quota should be set to
256.  Three /26s would be 192.  This mechanism encourages more efficient use of
the IPv4 space which will be increasingly important when working with globally
routable addresses.

For IPv6, the smallest viable subnet in Neutron is a /64.  There is no reason
to allocate a subnet of any other size for use on a Neutron network.  It would
look pretty funny to set a quota of 4611686018427387904 to allow one /64
subnet.  To avoid this, we count IPv6 quota in terms of /64s.  So, a quota of 3
allows three /64 subnets.  When we need to allocate something smaller in the
future, we will need to ensure that the code can handle non-integer quota
consumption.

Allocation
~~~~~~~~~~

Allocation is done in a way that aims to minimize fragmentation of the pool.
The relevant code is here [#]_.  First, the available prefixes are computed
using a set difference:  pool - allocations.  The result is compacted [#]_ and
then sorted by size.  The subnet is then allocated from the smallest available
prefix that is large enough to accommodate the request.

.. [#] neutron/ipam/subnet_alloc.py (_allocate_any_subnet)
.. [#] http://pythonhosted.org/netaddr/api.html#netaddr.IPSet.compact

Address Scopes
--------------

Before subnet pools or address scopes, it was impossible to tell if a network
address was routable in a certain context because the address was given
explicitly on subnet create and wasn't validated against any other addresses.
Address scopes are meant to solve this by putting control over the address
space in the hands of an authority:  the address scope owner.  It makes use of
the already existing SubnetPool concept for allocation.

Address scopes are "the thing within which address overlap is not allowed" and
thus provide more flexible control as well as decoupling of address overlap
from tenancy.

Prior to the Mitaka release, there was implicitly only a single 'shared'
address scope.  Arbitrary address overlap was allowed making it pretty much a
"free for all".  To make things seem somewhat sane, normal users are not able
to use routers to cross-plug networks from different projects and NAT was used
between internal networks and external networks.  It was almost as if each
project had a private address scope.

The problem is that this model cannot support use cases where NAT is not
desired or supported (e.g. IPv6) or we want to allow different projects to
cross-plug their networks.

An AddressScope covers only one address family.  But, they work equally well
for IPv4 and IPv6.

Routing
~~~~~~~

The reference implementation honors address scopes.  Within an address scope,
addresses route freely (barring any FW rules or other external restrictions).
Between scopes, routing is prevented unless address translation is used.

For now, floating IPs are the only place where traffic crosses scope
boundaries.  When a floating IP is associated to a fixed IP, the fixed IP is
allowed to access the address scope of the floating IP by way of a 1:1 NAT
rule. That means the fixed IP can access not only the external network, but
also any internal networks that are in the same address scope as the external
network. This is diagrammed as follows::

    +----------------------+      +---------------------------+
    |    address scope 1   |      |      address scope 2      |
    |                      |      |                           |
    | +------------------+ |      |   +------------------+    |
    | | internal network | |      |   | external network |    |
    | +-------------+----+ |      |   +--------+---------+    |
    |               |      |      |            |              |
    |       +-------+--+   |      |     +------+------+       |
    |       | fixed ip +----------------+ floating IP |       |
    |       +----------+   |      |     +--+--------+-+       |
    +----------------------+      |        |        |         |
                                  | +------+---+ +--+-------+ |
                                  | | internal | | internal | |
                                  | +----------+ +----------+ |
                                  +---------------------------+

Due to the asymmetric route in DVR, and the fact that DVR local routers do not
know the information of the floating IPs that reside in other hosts,
there is a limitation in the DVR multiple hosts scenario.  With DVR in
multiple hosts, when the destination of traffic is an internal fixed IP
in a different host, the fixed IP with a floating IP associated can't cross
the scope boundary to access the internal networks that are in the same
address scope of the external network.
See https://bugs.launchpad.net/neutron/+bug/1682228

RPC
~~~

The L3 agent in the reference implementation needs to know the address scope
for each port on each router in order to map ingress traffic correctly.

Each subnet from the same address family on a network is required to be from
the same subnet pool.  Therefore, the address scope will also be the same.  If
this were not the case, it would be more difficult to match ingress traffic on
a port with the appropriate scope.  It may be counter-intuitive but L3 address
scopes need to be anchored to some sort of non-L3 thing (e.g. an L2 interface)
in the topology in order to determine the scope of ingress traffic.  For now,
we use ports/networks.  In the future, we may be able to distinguish by
something else like the remote MAC address or something.

The address scope id is set on each port in a dict under the 'address_scopes'
attribute.  The scope is distinct per address family.  If the attribute does
not appear, it is assumed to be null for both families.  A value of null means
that the addresses are in the "implicit" address scope which holds all
addresses that don't have an explicit one.  All subnets that existed in Neutron
before address scopes existed fall here.

Here is an example of how the json will look in the context of a router port::

    "address_scopes": {
        "4": "d010a0ea-660e-4df4-86ca-ae2ed96da5c1",
        "6": null
    },

To implement floating IPs crossing scope boundaries, the L3 agent needs to know
the target scope of the floating ip.  The fixed address is not enough to
disambiguate because, theoretically, there could be overlapping addresses from
different scopes.  The scope is computed [#]_ from the floating ip fixed port
and attached to the floating ip dict under the 'fixed_ip_address_scope'
attribute.  Here's what the json looks like (trimmed)::

    {
         ...
         "floating_ip_address": "172.24.4.4",
         "fixed_ip_address": "172.16.0.3",
         "fixed_ip_address_scope": "d010a0ea-660e-4df4-86ca-ae2ed96da5c1",
         ...
    }

.. [#] neutron/db/l3_db.py (_get_sync_floating_ips)

Model
~~~~~

The model for subnet pools and address scopes can be found in
neutron/db/models_v2.py and neutron/db/address_scope_db.py.  This document
won't go over all of the details.  It is worth noting how they relate to
existing Neutron objects.  The existing Neutron subnet now optionally
references a single subnet pool::

    +----------------+        +------------------+        +--------------+
    | Subnet         |        | SubnetPool       |        | AddressScope |
    +----------------+        +------------------+        +--------------+
    | subnet_pool_id +------> | address_scope_id +------> |              |
    |                |        |                  |        |              |
    |                |        |                  |        |              |
    |                |        |                  |        |              |
    +----------------+        +------------------+        +--------------+

L3 Agent
~~~~~~~~

The L3 agent is limited in its support for multiple address scopes.  Within a
router in the reference implementation, traffic is marked on ingress with the
address scope corresponding to the network it is coming from.  If that traffic
would route to an interface in a different address scope, the traffic is
blocked unless an exception is made.

One exception is made for floating IP traffic.  When traffic is headed to a
floating IP, DNAT is applied and the traffic is allowed to route to the private
IP address potentially crossing the address scope boundary.  When traffic
flows from an internal port to the external network and a floating IP is
assigned, that traffic is also allowed.

Another exception is made for traffic from an internal network to the external
network when SNAT is enabled.  In this case, SNAT to the router's fixed IP
address is applied to the traffic.  However, SNAT is not used if the external
network has an explicit address scope assigned and it matches the internal
network's.  In that case, traffic routes straight through without NAT.  The
internal network's addresses are viable on the external network in this case.

The reference implementation has limitations.  Even with multiple address
scopes, a router implementation is unable to connect to two networks with
overlapping IP addresses.  There are two reasons for this.

First, a single routing table is used inside the namespace.  An implementation
using multiple routing tables has been in the works but there are some
unresolved issues with it.

Second, the default SNAT feature cannot be supported with the current Linux
conntrack implementation unless a double NAT is used (one NAT to get from the
address scope to an intermediate address specific to the scope and a second NAT
to get from that intermediate address to an external address).  Single NAT
won't work if there are duplicate addresses across the scopes.

Due to these complications the router will still refuse to connect to
overlapping subnets.  We can look in to an implementation that overcomes these
limitations in the future.
