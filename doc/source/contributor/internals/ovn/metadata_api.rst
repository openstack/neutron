.. _metadata_api:

==============================
OpenStack Metadata API and OVN
==============================

Introduction
------------

OpenStack Nova presents a metadata API to VMs similar to what is available on
Amazon EC2.  Neutron is involved in this process because the source IP address
is not enough to uniquely identify the source of a metadata request since
networks can have overlapping IP addresses.  Neutron is responsible for
intercepting metadata API requests and adding HTTP headers which uniquely
identify the source of the request before forwarding it to the metadata API
server.

The purpose of this document is to propose a design for how to enable this
functionality when OVN is used as the backend for OpenStack Neutron.

Neutron and Metadata Today
--------------------------

The following blog post describes how VMs access the metadata API through
Neutron today.

https://www.suse.com/communities/blog/vms-get-access-metadata-neutron/

In summary, we run a metadata proxy in either the router namespace or DHCP
namespace.  The DHCP namespace can be used when there's no router connected to
the network.  The one downside to the DHCP namespace approach is that it
requires pushing a static route to the VM through DHCP so that it knows to
route metadata requests to the DHCP server IP address.

* Instance sends a HTTP request for metadata to 169.254.169.254

* This request either hits the router or DHCP namespace depending on the route
  in the instance

* The metadata proxy service in the namespace adds the following info to the
  request:

  * Instance IP (X-Forwarded-For header)

  * Router or Network-ID (X-Neutron-Network-Id or X-Neutron-Router-Id header)

* The metadata proxy service sends this request to the metadata agent (outside
  the namespace) via a UNIX domain socket.

* The neutron-metadata-agent service forwards the request to the Nova metadata
  API service by adding some new headers (instance ID and Tenant ID) to the
  request [0].

For proper operation, Neutron and Nova must be configured to communicate
together with a shared secret. Neutron uses this secret to sign the Instance-ID
header of the metadata request to prevent spoofing. This secret is configured
through metadata_proxy_shared_secret on both nova and neutron configuration
files (optional).

[0] https://opendev.org/openstack/neutron/src/commit/f73f39f2cfcd4eace2bda14c99ead9a8cc8560f4/neutron/agent/metadata/agent.py#L175

Neutron and Metadata with OVN
-----------------------------

The current metadata API approach does not translate directly to OVN.  There
are no Neutron agents in use with OVN.  Further, OVN makes no use of its own
network namespaces that we could take advantage of like the original
implementation makes use of the router and dhcp namespaces.

We must use a modified approach that fits the OVN model.  This section details
a proposed approach.

Overview of Proposed Approach
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The proposed approach would be similar to the *isolated network* case in the
current ML2+OVS implementation. Therefore, we would be running a metadata
proxy (haproxy) instance on every hypervisor for each network a VM on that
host is connected to.

The downside of this approach is that we'll be running more metadata proxies
than we're doing now in case of routed networks (one per virtual router) but
since haproxy is very lightweight and they will be idling most of the time,
it shouldn't be a big issue overall. However, the major benefit of this
approach is that we don't have to implement any scheduling logic to distribute
metadata proxies across the nodes, nor any HA logic. This, however, can be
evolved in the future as explained below in this document.

Also, this approach relies on a new feature in OVN that we must implement
first so that an OVN port can be present on *every* chassis (similar to
*localnet* ports). This new type of logical port would be *localport* and we
will never forward packets over a tunnel for these ports. We would only send
packets to the local instance of a *localport*.

**Step 1** - Create a port for the metadata proxy

When using the DHCP agent today, Neutron automatically creates a port for the
DHCP agent to use.  We could do the same thing for use with the metadata proxy
(haproxy). We'll create an OVN *localport* which will be present on every
chassis and this port will have the same MAC/IP address on every host.
Eventually, we can share the same neutron port for both DHCP and metadata.

**Step 2** - Routing metadata API requests to the correct Neutron port

This works similarly to the current approach.

We would program OVN to include a static route in DHCP responses that routes
metadata API requests to the *localport* that is hosting the metadata API
proxy.

Also, in case DHCP isn't enabled or the client ignores the route info, we
will program a static route in the OVN logical router which will still get
metadata requests directed to the right place.

If the DHCP route does not work and the network is isolated, VMs won't get
metadata, but this already happens with the current implementation so this
approach doesn't introduce a regression.

**Step 3** - Management of the namespaces and haproxy instances

We propose a new agent called ``neutron-ovn-metadata-agent``.
We will run this agent on every hypervisor and it will be responsible for
spawning the haproxy instances for managing the OVS interfaces, network
namespaces and haproxy processes used to proxy metadata API requests.

**Step 4** - Metadata API request processing

Similar to the existing neutron metadata agent, ``neutron-ovn-metadata-agent``
must act as an intermediary between haproxy and the Nova metadata API service.
``neutron-ovn-metadata-agent`` is the process that will have access to the
host networks where the Nova metadata API exists.  Each haproxy will be in a
network namespace not able to reach the appropriate host network.  Haproxy
will add the necessary headers to the metadata API request and then forward it
to ``neutron-ovn-metadata-agent`` over a UNIX domain socket, which matches the
behavior of the current metadata agent.


Metadata Proxy Management Logic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In neutron-ovn-metadata-agent.

* On startup:

  * Do a full sync. Ensure we have all the required metadata proxies running.
    For that, the agent would watch the ``Port_Binding`` table of the OVN
    Southbound database and look for all rows with the ``chassis`` column set
    to the host the agent is running on. For all those entries, make sure a
    metadata proxy instance is spawned for every ``datapath`` (Neutron
    network) those ports are attached to. Ensure any running metadata proxies
    no longer needed are torn down.

* Open and maintain a connection to the OVN Northbound database (using the
  ovsdbapp library).  On first connection, and anytime a reconnect happens:

  * Do a full sync.

* Register a callback for creates/updates/deletes to Logical_Switch_Port rows
  to detect when metadata proxies should be started or torn down.
  ``neutron-ovn-metadata-agent`` will watch OVN Southbound database
  (``Port_Binding`` table) to detect when a port gets bound to its chassis. At
  that point, the agent will make sure that there's a metadata proxy
  attached to the OVN *localport* for the network which this port is connected
  to.

* When a new network is created, we must create an OVN *localport* for use
  as a metadata proxy. This port will be owned by ``network:dhcp`` so that it
  gets auto deleted upon the removal of the network and it will remain ``DOWN``
  and not bound to any chassis. The metadata port will be created regardless of
  the DHCP setting of the subnets within the network as long as the metadata
  service is enabled.

* When a network is deleted, we must tear down the metadata proxy instance (if
  present) on the host and delete the corresponding OVN *localport* (which will
  happen automatically as it's owned by ``network:dhcp``).

Launching a metadata proxy includes:

* Creating a network namespace::

    $ sudo ip netns add <ns-name>

* Creating a VETH pair (OVS upgrades that upgrade the kernel module will make
  internal ports go away and then brought back by OVS scripts. This may cause
  some disruption. Therefore, veth pairs are preferred over internal ports)::

    $ sudo ip link add <iface-name>0 type veth peer name <iface-name>1

* Creating an OVS interface and placing one end in that namespace::

    $ sudo ovs-vsctl add-port br-int <iface-name>0
    $ sudo ip link set <iface-name>1 netns <ns-name>

* Setting the IP and MAC addresses on that interface::

    $ sudo ip netns exec <ns-name> \
    > ip link set <iface-name>1 address <neutron-port-mac>
    $ sudo ip netns exec <ns-name> \
    > ip addr add <neutron-port-ip>/<netmask> dev <iface-name>1

* Bringing the VETH pair up::

    $ sudo ip netns exec <ns-name> ip link set <iface-name>1 up
    $ sudo ip link set <iface-name>0 up

* Set ``external-ids:iface-id=NEUTRON_PORT_UUID`` on the OVS interface so that
  OVN is able to correlate this new OVS interface with the correct OVN logical
  port::

    $ sudo ovs-vsctl set Interface <iface-name>0 external_ids:iface-id=<neutron-port-uuid>

* Starting haproxy in this network namespace.

Tearing down a metadata proxy includes:

* Removing the network UUID from our chassis.

* Stopping haproxy.

* Deleting the OVS interface.

* Deleting the network namespace.

**Other considerations**

This feature will be enabled by default when using ``ovn`` driver, but there
should be a way to disable it in case operators who don't need metadata don't
have to deal with the complexity of it (haproxy instances, network namespaces,
etcetera). In this case, the agent would not create the neutron ports needed
for metadata.

Right now, the ``vif-plugged`` event to Nova is sent out when the up column
in the OVN Northbound database's Logical_Switch_Port table changes to True,
indicating that the VIF is now up. There could be a race condition when the
first VM for a certain network boots on a hypervisor if it does so before the
metadata proxy instance has been spawned. Fortunately, retries on cloud-init
should eventually fetch metadata even when this might happen.

Alternatives Considered
-----------------------

Alternative 1: Build metadata support into ovn-controller
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We've been building some features useful to OpenStack directly into OVN. DHCP
and DNS are key examples of things we've replaced by building them into
ovn-controller.  The metadata API case has some key differences that make this
a less attractive solution:

The metadata API is an OpenStack specific feature.  DHCP and DNS by contrast
are more clearly useful outside of OpenStack. Building metadata API proxy
support into ovn-controller means embedding an HTTP and TCP stack into
ovn-controller.  This is a significant degree of undesired complexity.

This option has been ruled out for these reasons.

Alternative 2: Distributed metadata and High Availability
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this approach, we would spawn a metadata proxy per virtual router or per
network (if isolated), thus, improving the number of metadata proxy instances
running in the cloud. However, scheduling and HA have to be considered. Also,
we wouldn't need the OVN *localport* implementation.

``neutron-ovn-metadata-agent`` would run on any host that we wish to be able
to host metadata API proxies.  These hosts must also be running ovn-controller.

Each of these hosts will have a Chassis record in the OVN southbound database
created by ovn-controller.  The Chassis table has a column called
``external_ids`` which can be used for general metadata however we see fit.
``neutron-ovn-metadata-agent`` will update its corresponding Chassis record
with an external-id of ``neutron-metadata-proxy-host=true`` to indicate that
this OVN chassis is one capable of hosting metadata proxy instances.

Once we have a way to determine hosts capable of hosting metadata API proxies,
we can add logic to the ovn ML2 driver that schedules metadata API
proxies.  This would be triggered by Neutron API requests.

The output of the scheduling process would be setting an ``external_ids`` key
on a Logical_Switch_Port in the OVN northbound database that corresponds with
a metadata proxy.  The key could be something like
``neutron-metadata-proxy-chassis=CHASSIS_HOSTNAME``.

``neutron-ovn-metadata-agent`` on each host would also be watching for updates
to these Logical_Switch_Port rows.  When it detects that a metadata proxy has
been scheduled locally, it will kick off the process to spawn the local
haproxy instance and get it plugged into OVN.

HA must also be considered.  We must know when a host goes down so that all
metadata proxies scheduled to that host can be rescheduled.  This is almost
the exact same problem we have with L3 HA.  When a host goes down, we need to
trigger rescheduling gateways to other hosts.  We should ensure that the
approach used for rescheduling L3 gateways can be utilized for rescheduling
metadata proxies, as well.

In neutron-server (ovn mechanism driver) .

Introduce a new ovn driver configuration option:

* ``[ovn] isolated_metadata=[True|False]``

Events that trigger scheduling a new metadata proxy:

* If isolated_metadata is True

  * When a new network is created, we must create an OVN logical port for use
    as a metadata proxy and then schedule this to one of the
    ``neutron-ovn-metadata-agent`` instances.

* If isolated_metadata is False

  * When a network is attached to or removed from a logical router, ensure
    that at least one of the networks has a metadata proxy port already
    created. If not, pick a network and create a metadata proxy port and then
    schedule it to an agent. At this point, we need to update the static route
    for metadata API.

Events that trigger unscheduling an existing metadata proxy:

* When a network is deleted, delete the metadata proxy port if it exists and
  unschedule it from a ``neutron-ovn-metadata-agent``.

To schedule a new metadata proxy:

* Determine the list of available OVN Chassis that can host metadata proxies
  by reading the ``Chassis`` table of the OVN Southbound database.  Look for
  chassis that have an external-id of ``neutron-metadata-proxy-host=true``.

* Of the available OVN chassis, choose the one "least loaded", or currently
  hosting the fewest number of metadata proxies.

* Set ``neutron-metadata-proxy-chassis=CHASSIS_HOSTNAME`` as an external-id on
  the Logical_Switch_Port in the OVN Northbound database that corresponds to
  the neutron port used for this metadata proxy.  ``CHASSIS_HOSTNAME`` maps to
  the hostname row of a Chassis record in the OVN Southbound database.

This approach has been ruled out for its complexity although we have analyzed
the details deeply because, eventually, and depending on the implementation of
L3 HA, we will want to evolve to it.

Other References
----------------

* Haproxy config --
  https://review.openstack.org/#/c/431691/34/neutron/agent/metadata/driver.py

* https://engineeringblog.yelp.com/2015/04/true-zero-downtime-haproxy-reloads.html
