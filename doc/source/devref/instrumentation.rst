Neutron Instrumentation
=======================

OpenStack operators require information about the status and health
of the Neutron system. While it is possible for an operator to pull
all of the interface counters from compute and network nodes, today
there is no capability to aggregate that information to provide
comprehensive counters for each project within Neutron. Neutron
instrumentation sets out to meet this need.

Neutron instrumentation can be broken down into three major pieces:

#. Data Collection (i.e. what data should be collected and how),
#. Data Aggregation (i.e. how and where raw data should be aggregated
   into project information)
#. Data Consumption (i.e. how is aggregated data consumed)

While instrumentation might also be considered to include asynchronous event
notifications, like fault detection, this is considered out of scope
for the following two reasons:

#. In Kilo, Neutron added the ProcessManager class to allow agents to
   spawn a monitor thread that would either respawn or exit the agent.
   While this is a useful feature for ensuring that the agent gets
   restarted, the only notification of this event is an error log entry.
   To ensure that this event is asynchronously passed up to an upstream
   consumer, the Neutron logger object should have its publish_errors
   option set to True and the transport URL set to the point at the
   upstream consumer. As the particular URL is consumer specific, further
   discussion is outside the scope of this section.
#. For the data plane, it is necessary to have visibility into the hardware
   status of the compute and networking nodes. As some upstream consumers
   already support this (even incompletely) it is considered to be within
   the scope of the upstream consumer and not Neutron itself.

How does Instrumentation differ from Metering Labels and Rules
--------------------------------------------------------------

The existing metering label and rule extension provides the ability to
collect traffic information on a per CIDR basis. Therefore, a possible
implementation of instrumentation would be to use per-instance metering
rules for all IP addresses in both directions. However, the information
collected by metering rules is focused more on billing and so does not
have the desired granularity (i.e. it counts transmitted packets without
keeping track of what caused packets to fail).

What Data to Collect
--------------------

The first step is to consider what data to collect. In the absence of a
standard, it is proposed to use the information set defined in
[RFC2863]_ and [RFC4293]_. This proposal should not be read as implying
that Neutron instrumentation data will be browsable via a MIB browser as
that would be a potential Data Consumption model.

.. [RFC2863] https://tools.ietf.org/html/rfc2863
.. [RFC4293] https://tools.ietf.org/html/rfc4293

For the reference implementation (Nova/VIF, OVS, and Linux Bridge), this
section identifies what data is already available and how it can be
mapped into the structures defined by the RFC. Other plugins are welcome
to define either their own data sets and/or their own mappings
to the data sets defined in the referenced RFCs.

Focus here is on what is available from "stock" Linux and OpenStack.
Additional statistics may become available if other items like NetFlow or
sFlow are added to the mix, but those should be covered as an addition to
the basic information discussed here.

What is Available from Nova
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Within Nova, the libvirt driver makes the following host traffic statistics
available under the get_diagnostics() and get_instance_diagnostics() calls
on a per-virtual NIC basis:

* Receive bytes, packets, errors and drops
* Transmit bytes, packets, errors and drops

There continues to be a long running effort to get these counters into
Ceilometer (the wiki page at [#]_ attempted to do this via a direct call
while [#]_ is trying to accomplish this via notifications from Nova).
Rather than propose another way for collecting these statistics from Nova,
this devref takes the approach of declaring them out of scope until there is
an agreed upon method for getting the counters from Nova to Ceilometer and
then see if Neutron can/should piggy-back off of that.

.. [#] https://wiki.openstack.org/wiki/EfficientMetering/FutureNovaInteractionModel
.. [#] http://lists.openstack.org/pipermail/openstack-dev/2015-June/067589.html

What is Available from Linux Bridge
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For the Linux bridge, a check of [#]_ shows that IEEE 802.1d
mandated statistics are only a "wishlist" item. The alternative
is to use NETLINK/shell to list the interfaces attached to
a particular bridge and then to collect statistics for each
interface attached to the bridge. These statistics could then
be mapped to appropriate places, as discussed below.

Note: the examples below talk in terms of mapping counters
available from the Linux operating system:

* Receive bytes, packets, errors, dropped, overrun and multicast
* Transmit bytes, packets, errors, dropped, carrier and collisions

Available counters for interfaces on other operating systems
can be mapped in a similar fashion.

.. [#] http://git.kernel.org/cgit/linux/kernel/git/shemminger/bridge-utils.git/tree/doc/WISHLIST

Of interest are counters from the each of the following (as of this writing,
Linux Bridge only supports legacy routers, so the DVR case need not be
considered):

* Compute node

* * Instance tap interface

* Network node

  * DHCP namespace tap interface (if defined)
  * Router namespace qr interface
  * Router namespace qg interface

What is Available from Openvswitch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Like Linux bridge, the openvswitch implementation has interface counters
that will be collected of interest are the receive and transmit counters
from the following:

Legacy Routing
++++++++++++++

* Compute node

* * Instance tap interface

* Network node

  * DHCP namespace tap interface (if defined)
  * Router namespace qr interface
  * Router namespace qg interface

Distributed Routing (DVR)
+++++++++++++++++++++++++

* Compute node

* * Instance tap interface
* * Router namespace qr interface
* * FIP namespace fg interface

* Network node

  * DHCP tap interface (if defined)
  * Router namespace qr interface
  * SNAT namespace qg interface

Mapping from Available Information to MIB Data Set
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following table summarizes how the interface counters are mapped
into each MIB Data Set. Specific details are covered in the sections
below:

+---------+--------------+----------------------+
| Node    | Interface    | Included in Data Set |
|         |              +-----------+----------+
|         |              | RFC2863   | RFC4293  |
+=========+==============+===========+==========+
| Compute | Instance tap | Yes       | No       |
|         +--------------+-----------+----------+
|         | Router qr    | Yes       | Yes      |
|         +--------------+-----------+----------+
|         | FIP fg       | No        | Yes      |
+---------+--------------+-----------+----------+
| Network | DHCP tap     | Yes       | No       |
|         +--------------+-----------+----------+
|         | Router qr    | Yes       | Yes      |
|         +--------------+-----------+----------+
|         | Router qg    | No        | Yes      |
|         +--------------+-----------+----------+
|         | SNAT sg      | No        | Yes      |
+---------+--------------+-----------+----------+

Note: because of replication of the router qg interface when running
distributed routing, aggregation of the individual counter information
will be necessary to fill in the appropriate data set entries. This
will be covered in the Data Aggregation section below:

RFC 2863 Structures
+++++++++++++++++++

For each compute host, each network will be represented with a
"switch", modeled by instances of ifTable and ifXTable. This
mapping has the advantage that for a particular network, the
view to the project or the operator is identical - the only
difference is that the operator can see all networks, while a
project will only see the networks under their project id.

The current reference implementation identifies tap interface names with
the Neutron port they are associated with. In turn, the Neutron port
identifies the Neutron network. Therefore, it is possible to take counters
from each tap interface and map them into entries in the appropriate tables,
using the following proposed assignments:

* ifTable

  * ifInOctets = low 32 bits of interface received byte count
  * ifInUcastPkts = low 32 bits of interface received packet count
  * ifInDiscards = interface received dropped count
  * ifInErrors = interface received errors count
  * ifOutOctets = low 32 bits of interface transmit byte count
  * ifOutUcastPkts = low 32 bits of interface transmit packet count
  * ifOutDiscards = interface transmit dropped count
  * ifOutErrors = interface transmit errors count

* ifXTable

  * ifHCInOctets = 64 bits of interface received byte count
  * ifHCInUcastPkts = 64 bits of interface received packet count
  * ifHCOctOctets = 64 bits of interface transmit byte count
  * ifHCOctUcastPkts = 64 bits of interface transmit packet count

Section 3.1.6 of [RFC2863]_ provides the details of why 64-bit sized
counters need to be supported. The summary is that with increasing
transmission bandwidth use of 32-bit counters would require a
problematic increase in counter polling frequency (a 1Gbs stream of
full-sized packets will cause a 32-bit counter to wrap in 34 seconds).

RFC 4293 Structures
+++++++++++++++++++

Counters tracked by RFC 4293 come in two flavors: ones that are
inherited from the interface, and those that track L3 events,
such as fragmentation, re-assembly, truncations, etc. As the current
instrumentation available from the reference implementation does not
provide appropriate source information, the following counters are
declared out of scope for this devref:

* ipSystemStatsInHdrErrors, ipIfStatsInHdrErrors
* ipSystemStatsInNoRoutes, ipIfStatsInNoRoutes
* ipSystemStatsInAddrErrors, ipIfStatsInAddrErrors
* ipSystemStatsInUnknownProtos, ipIfStatsInUnknownProtos
* ipSystemStatsInTruncatedPkts, ipIfStatsInTruncatedPkts
* ipSystemStatsInForwDatagrams, ipIfStatsInForwDatagrams
* ipSystemStatsHCInForwDatagrams, ipIfStatsHCInForwDatagrams
* ipSystemStatsReasmReqds, ipIfStatsReasmReqds
* ipSystemStatsReasmOKs, ipIfStatsReasmOKs
* ipSystemStatsReasmFails, ipIfStatsReasmFails
* ipSystemStatsInDelivers, ipIfStatsInDelivers
* ipSystemStatsHCInDelivers, ipIfStatsHCInDelivers
* ipSystemStatsOutRequests, ipIfStatsOutRequests
* ipSystemStatsHCOutRequests, ipIfStatsHCOutRequests
* ipSystemStatsOutNoRoutes, ipIfStatsOutNoRoutes
* ipSystemStatsOutForwDatagrams, ipIfStatsOutForwDatagrams
* ipSystemStatsHCOutForwDatagrams, ipIfStatsHCOutForwDatagrams
* ipSystemStatsOutFragReqds, ipIfStatsOutFragReqds
* ipSystemStatsOutFragOKs, ipIfStatsOutFragOKs
* ipSystemStatsOutFragFails, ipIfStatsOutFragFails
* ipSystemStatsOutFragCreates, ipIfStatsOutFragCreates

In ipIfStatsTable, the following counters will hold the same
value as the referenced counter from RFC 2863:

* ipIfStatsInReceives :== ifInUcastPkts
* ipIfStatsHCInReceives :== ifInHCUcastPkts
* ipIfStatsInOctets :== ifInOctets
* ipIfStatsHCInOctets :== ifInHCOctets
* ipIfStatsInDiscard :== ifInDiscards
* ipIfStatsOutDiscard :== ifOutDiscards
* ipIfStatsOutTransmits :== ifOutUcastPkts
* ipIfStatsHCOutTransmits :== ifHCOutUcastPkts
* ipIfStatsOutOctets :== ifOutOctets
* ipIfStatsHCOutOctets :== ifHCOutOctets

For ipSystemStatsTable, the following counters will hold values based
on the following assignments. Thess summations are covered in more detail
in the Data Aggregation section below

* ipSystemStatsInReceives :== sum of all ipIfStatsInReceives for the router
* ipSystemStatsHCInReceives :== sum of all ipIfStatsHCInReceives for the router
* ipSystemStatsInOctets :== sum of all ipIfStatsInOctets for the router
* ipSystemStatsHCInOctets :== sum of all ipIfStatsHCInOctets for the router
* ipSystemStatsInDiscard :== sum of all ipIfStatsInDiscard for the router
* ipSystemStatsOutDiscard :== sum of all ipIfStatsOutDiscard for the router
* ipSystemStatsOutTransmits :== sum of all ipIfStatsOutTrasmit for the router
* ipSystemStatsHCOutTransmits :== sum of all ipIfStatsHCOutTrasmit for the
  router
* ipSystemStatsOutOctets :== sum of all ipIfStatsOctOctets for the router
* ipSystemStatsHCOutOctets :== sum of all ipIfStatsHCOutOctets for the router

Data Collection
---------------

There are two options for how data can be collected:

#. The Neutron L3 and ML2 agents could collect the counters themselves.
#. A separate collection agent could be started on each compute/network node
   to collect counters.

Because of the number of counters needed to be collected (for example,
a cloud running legacy routing would need to collect (for each project)
three counters from a network node and a tap counter for each running
instance. While it would be desirable to reuse the existing L3 and ML2 agents,
the initial proof of concept will run a separate agent that will use
a separate threads to isolate the effects of counter collection from
reporting. Once the performance of the collection agent is understood,
then merging the functionality into the L3 or ML2 agents can be considered.
The collection thread will initially use shell commands via rootwrap, with
the plan of moving to native python libraries when support for them is
available.

In addition, there are two options for how to report counters back to the
Neutron server: push or pull (or asynchronous notification vs polling).
On the one hand, pull/polling eases the Neutron server's task in that it
only needs to store/aggregate the results from the current polling cycle.
However, this comes at the cost of dealing with the stale data issues that
scaling a polling cycle will entail. On the other hand, asynchronous
notification requires that the Neutron server has the capability to hold
the current results from each collector. As the L3 and ML2 agents already
have use asynchronous notification to report status back to the Neutron
server, the proof of concept will follow the same model to ease a future
merging of functionality.

Data Aggregation
----------------

Will be covered in a follow-on patch set.

Data Consumption
----------------

Will be covered in a follow-on patch set.
