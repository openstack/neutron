.. _adv-features:

========================================
Advanced features through API extensions
========================================

Several plug-ins implement API extensions that provide capabilities
similar to what was available in ``nova-network``. These plug-ins are likely
to be of interest to the OpenStack community.

Provider networks
~~~~~~~~~~~~~~~~~

Networks can be categorized as either project networks or provider
networks. Project networks are created by normal users and details about
how they are physically realized are hidden from those users. Provider
networks are created with administrative credentials, specifying the
details of how the network is physically realized, usually to match some
existing network in the data center.

Provider networks enable administrators to create networks that map
directly to the physical networks in the data center.
This is commonly used to give projects direct access to a public network
that can be used to reach the Internet. It might also be used to
integrate with VLANs in the network that already have a defined meaning
(for example, enable a VM from the marketing department to be placed
on the same VLAN as bare-metal marketing hosts in the same data center).

The provider extension allows administrators to explicitly manage the
relationship between Networking virtual networks and underlying physical
mechanisms such as VLANs and tunnels. When this extension is supported,
Networking client users with administrative privileges see additional
provider attributes on all virtual networks and are able to specify
these attributes in order to create provider networks.

The provider extension is supported by the Open vSwitch and Linux Bridge
plug-ins. Configuration of these plug-ins requires familiarity with this
extension.

Terminology
-----------

A number of terms are used in the provider extension and in the
configuration of plug-ins supporting the provider extension:

.. list-table:: **Provider extension terminology**
   :widths: 30 70
   :header-rows: 1

   * - Term
     - Description
   * - virtual network
     - A Networking L2 network (identified by a UUID and optional name) whose
       ports can be attached as vNICs to Compute instances and to various
       Networking agents. The Open vSwitch and Linux Bridge plug-ins each
       support several different mechanisms to realize virtual networks.
   * - physical network
     - A network connecting virtualization hosts (such as compute nodes) with
       each other and with other network resources. Each physical network might
       support multiple virtual networks. The provider extension and the plug-in
       configurations identify physical networks using simple string names.
   * - project network
     - A virtual network that a project or an administrator creates. The
       physical details of the network are not exposed to the project.
   * - provider network
     - A virtual network administratively created to map to a specific network
       in the data center, typically to enable direct access to non-OpenStack
       resources on that network. Project can be given access to provider
       networks.
   * - VLAN network
     - A virtual network implemented as packets on a specific physical network
       containing IEEE 802.1Q headers with a specific VID field value. VLAN
       networks sharing the same physical network are isolated from each other
       at L2 and can even have overlapping IP address spaces. Each distinct
       physical network supporting VLAN networks is treated as a separate VLAN
       trunk, with a distinct space of VID values. Valid VID values are 1
       through 4094.
   * - flat network
     - A virtual network implemented as packets on a specific physical network
       containing no IEEE 802.1Q header. Each physical network can realize at
       most one flat network.
   * - local network
     - A virtual network that allows communication within each host, but not
       across a network. Local networks are intended mainly for single-node test
       scenarios, but can have other uses.
   * - GRE network
     - A virtual network implemented as network packets encapsulated using
       GRE. GRE networks are also referred to as *tunnels*. GRE tunnel packets
       are routed by the IP routing table for the host, so GRE networks are not
       associated by Networking with specific physical networks.
   * - Virtual Extensible LAN (VXLAN) network
     - VXLAN is a proposed encapsulation protocol for running an overlay network
       on existing Layer 3 infrastructure. An overlay network is a virtual
       network that is built on top of existing network Layer 2 and Layer 3
       technologies to support elastic compute architectures.

The ML2, Open vSwitch, and Linux Bridge plug-ins support VLAN networks,
flat networks, and local networks. Only the ML2 and Open vSwitch
plug-ins currently support GRE and VXLAN networks, provided that the
required features exist in the hosts Linux kernel, Open vSwitch, and
iproute2 packages.

Provider attributes
-------------------

The provider extension extends the Networking network resource with
these attributes:


.. list-table:: **Provider network attributes**
   :widths: 10 10 10 49
   :header-rows: 1

   * - Attribute name
     - Type
     - Default Value
     - Description
   * - provider: network\_type
     - String
     - N/A
     - The physical mechanism by which the virtual network is implemented.
       Possible values are ``flat``, ``vlan``, ``local``, ``gre``, and
       ``vxlan``, corresponding to flat networks, VLAN networks, local
       networks, GRE networks, and VXLAN networks as defined above.
       All types of provider networks can be created by administrators,
       while project networks can be implemented as ``vlan``, ``gre``,
       ``vxlan``, or ``local`` network types depending on plug-in
       configuration.
   * - provider: physical_network
     - String
     - If a physical network named "default" has been configured and
       if provider:network_type is ``flat`` or ``vlan``, then "default"
       is used.
     - The name of the physical network over which the virtual network
       is implemented for flat and VLAN networks. Not applicable to the
       ``local``, ``vxlan`` or ``gre`` network types.
   * - provider:segmentation_id
     - Integer
     - N/A
     - For VLAN networks, the VLAN VID on the physical network that
       realizes the virtual network. Valid VLAN VIDs are 1 through 4094.
       For GRE networks, the tunnel ID. Valid tunnel IDs are any 32 bit
       unsigned integer. Not applicable to the ``flat`` or ``local``
       network types.

To view or set provider extended attributes, a client must be authorized
for the ``extension:provider_network:view`` and
``extension:provider_network:set`` actions in the Networking policy
configuration. The default Networking configuration authorizes both
actions for users with the admin role. An authorized client or an
administrative user can view and set the provider extended attributes
through Networking API calls. See the section called
:ref:`Authentication and authorization` for details on policy configuration.

.. _L3-routing-and-NAT:

L3 routing and NAT
~~~~~~~~~~~~~~~~~~

The Networking API provides abstract L2 network segments that are
decoupled from the technology used to implement the L2 network.
Networking includes an API extension that provides abstract L3 routers
that API users can dynamically provision and configure. These Networking
routers can connect multiple L2 Networking networks and can also provide
a gateway that connects one or more private L2 networks to a shared
external network. For example, a public network for access to the
Internet. See the `OpenStack Configuration Reference <https://docs.
openstack.org/ocata/config-reference/>`_ for details on common
models of deploying Networking L3 routers.

The L3 router provides basic NAT capabilities on gateway ports that
uplink the router to external networks. This router SNATs all traffic by
default and supports floating IPs, which creates a static one-to-one
mapping from a public IP on the external network to a private IP on one
of the other subnets attached to the router. This allows a project to
selectively expose VMs on private networks to other hosts on the
external network (and often to all hosts on the Internet). You can
allocate and map floating IPs from one port to another, as needed.

Basic L3 operations
-------------------

External networks are visible to all users. However, the default policy
settings enable only administrative users to create, update, and delete
external networks.

This table shows example :command:`openstack` commands that enable you
to complete basic L3 operations:

.. list-table:: **Basic L3 Operations**
   :widths: 30 50
   :header-rows: 1

   * - Operation
     - Command
   * - Creates external networks.
     - .. code-block:: console

          $ openstack network create public --external
          $ openstack subnet create --network public --subnet-range 172.16.1.0/24 subnetname
   * - Lists external networks.
     - .. code-block:: console

          $ openstack network list --external
   * - Creates an internal-only router that connects to multiple L2 networks privately.
     - .. code-block:: console

          $ openstack network create net1
          $ openstack subnet create --network net1 --subnet-range 10.0.0.0/24 subnetname1
          $ openstack network create net2
          $ openstack subnet create --network net2 --subnet-range 10.0.1.0/24 subnetname2
          $ openstack router create router1
          $ openstack router add subnet router1 subnetname1
          $ openstack router add subnet router1 subnetname2

       An internal router port can have only one IPv4 subnet and multiple IPv6 subnets
       that belong to the same network ID. When you call ``router-interface-add`` with an IPv6
       subnet, this operation adds the interface to an existing internal port with the same
       network ID. If a port with the same network ID does not exist, a new port is created.

   * - Connects a router to an external network, which enables that router to
       act as a NAT gateway for external connectivity.
     - .. code-block:: console

          $ openstack router set --external-gateway EXT_NET_ID router1
          $ openstack router set --route destination=172.24.4.0/24,gateway=172.24.4.1 router1

       The router obtains an interface with the gateway_ip address of the
       subnet and this interface is attached to a port on the L2 Networking
       network associated with the subnet. The router also gets a gateway
       interface to the specified external network. This provides SNAT
       connectivity to the external network as well as support for floating
       IPs allocated on that external networks. Commonly an external network
       maps to a network in the provider.

   * - Lists routers.
     - .. code-block:: console

          $ openstack router list
   * - Shows information for a specified router.
     - .. code-block:: console

          $ openstack router show ROUTER_ID
   * - Shows all internal interfaces for a router.
     - .. code-block:: console

          $ openstack port list --router  ROUTER_ID
          $ openstack port list --router  ROUTER_NAME
   * - Identifies the PORT_ID that represents the VM NIC to which the floating
       IP should map.
     - .. code-block:: console

          $ openstack port list -c ID -c "Fixed IP Addresses" --server INSTANCE_ID

       This port must be on a Networking subnet that is attached to
       a router uplinked to the external network used to create the floating
       IP. Conceptually, this is because the router must be able to perform the
       Destination NAT (DNAT) rewriting of packets from the floating IP address
       (chosen from a subnet on the external network) to the internal fixed
       IP (chosen from a private subnet that is behind the router).

   * - Creates a floating IP address and associates it with a port.
     - .. code-block:: console

          $ openstack floating ip create EXT_NET_ID
          $ openstack floating ip add port FLOATING_IP_ID --port-id INTERNAL_VM_PORT_ID

   * - Creates a floating IP on a specific subnet in the external network.
     - .. code-block:: console

         $ openstack floating ip create EXT_NET_ID --subnet SUBNET_ID

       If there are multiple subnets in the external network, you can choose a specific
       subnet based on quality and costs.

   * - Creates a floating IP address and associates it with a port, in a single step.
     - .. code-block:: console

          $ openstack floating ip create --port INTERNAL_VM_PORT_ID EXT_NET_ID
   * - Lists floating IPs
     - .. code-block:: console

          $ openstack floating ip list
   * - Finds floating IP for a specified VM port.
     - .. code-block:: console

          $ openstack floating ip list --port INTERNAL_VM_PORT_ID
   * - Disassociates a floating IP address.
     - .. code-block:: console

          $ openstack floating ip remove port FLOATING_IP_ID
   * - Deletes the floating IP address.
     - .. code-block:: console

          $ openstack floating ip delete FLOATING_IP_ID
   * - Clears the gateway.
     - .. code-block:: console

          $ openstack router unset --external-gateway router1
   * - Removes the interfaces from the router.
     - .. code-block:: console

          $ openstack router remove subnet router1 SUBNET_ID

       If this subnet ID is the last subnet on the port, this operation deletes the port itself.

   * - Deletes the router.
     - .. code-block:: console

          $ openstack router delete router1

Security groups
~~~~~~~~~~~~~~~

Security groups and security group rules allow administrators and
projects to specify the type of traffic and direction
(ingress/egress) that is allowed to pass through a port. A security
group is a container for security group rules.

When a port is created in Networking it is associated with a security
group. If a security group is not specified the port is associated with
a 'default' security group. By default, this group drops all ingress
traffic and allows all egress. Rules can be added to this group in order
to change the behavior.

To use the Compute security group APIs or use Compute to orchestrate the
creation of ports for instances on specific security groups, you must
complete additional configuration. You must configure the
``/etc/nova/nova.conf`` file and set the ``use_neutron=True``
option on every node that runs nova-compute, nova-conductor and nova-api.
After you make this change, restart those nova services to pick up this change.
Then, you can use both the Compute and OpenStack Network security group
APIs at the same time.

.. note::

   -  To use the Compute security group API with Networking, the
      Networking plug-in must implement the security group API. The
      following plug-ins currently implement this: ML2, Open vSwitch,
      Linux Bridge, NEC, and VMware NSX.

   -  You must configure the correct firewall driver in the
      ``securitygroup`` section of the plug-in/agent configuration
      file. Some plug-ins and agents, such as Linux Bridge Agent and
      Open vSwitch Agent, use the no-operation driver as the default,
      which results in non-working security groups.

   -  When using the security group API through Compute, security
      groups are applied to all ports on an instance. The reason for
      this is that Compute security group APIs are instances based and
      not port based as Networking.

   -  When creating or updating a port with a specified security group,
      the admin tenant can use the security groups of other tenants.

Basic security group operations
-------------------------------

This table shows example neutron commands that enable you to complete
basic security group operations:

.. list-table:: **Basic security group operations**
   :widths: 30 50
   :header-rows: 1

   * - Operation
     - Command
   * - Creates a security group for our web servers.
     - .. code-block:: console

          $ openstack security group create webservers \
           --description "security group for webservers"
   * - Lists security groups.
     - .. code-block:: console

          $ openstack security group list
   * - Creates a security group rule to allow port 80 ingress.
     - .. code-block:: console

          $ openstack security group rule create --ingress \
            --protocol tcp SECURITY_GROUP_UUID
   * - Lists security group rules.
     - .. code-block:: console

          $ openstack security group rule list
   * - Deletes a security group rule.
     - .. code-block:: console

          $ openstack security group rule delete SECURITY_GROUP_RULE_UUID
   * - Deletes a security group.
     - .. code-block:: console

          $ openstack security group delete SECURITY_GROUP_UUID
   * - Creates a port and associates two security groups.
     - .. code-block:: console

          $ openstack port create port1 --security-group SECURITY_GROUP_ID1 \
            --security-group SECURITY_GROUP_ID2 --network NETWORK_ID
   * - Removes security groups from a port.
     - .. code-block:: console

          $ openstack port set --no-security-group PORT_ID

Plug-in specific extensions
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each vendor can choose to implement additional API extensions to the
core API. This section describes the extensions for each plug-in.

VMware NSX extensions
---------------------

These sections explain NSX plug-in extensions.

VMware NSX QoS extension
^^^^^^^^^^^^^^^^^^^^^^^^

The VMware NSX QoS extension rate-limits network ports to guarantee a
specific amount of bandwidth for each port. This extension, by default,
is only accessible by a project with an admin role but is configurable
through the ``policy.json`` file. To use this extension, create a queue
and specify the min/max bandwidth rates (kbps) and optionally set the
QoS Marking and DSCP value (if your network fabric uses these values to
make forwarding decisions). Once created, you can associate a queue with
a network. Then, when ports are created on that network they are
automatically created and associated with the specific queue size that
was associated with the network. Because one size queue for a every port
on a network might not be optimal, a scaling factor from the nova flavor
``rxtx_factor`` is passed in from Compute when creating the port to scale
the queue.

Lastly, if you want to set a specific baseline QoS policy for the amount
of bandwidth a single port can use (unless a network queue is specified
with the network a port is created on) a default queue can be created in
Networking which then causes ports created to be associated with a queue
of that size times the rxtx scaling factor. Note that after a network or
default queue is specified, queues are added to ports that are
subsequently created but are not added to existing ports.

Basic VMware NSX QoS operations
'''''''''''''''''''''''''''''''

This table shows example neutron commands that enable you to complete
basic queue operations:

.. list-table:: **Basic VMware NSX QoS operations**
   :widths: 30 50
   :header-rows: 1

   * - Operation
     - Command
   * - Creates QoS queue (admin-only).
     - .. code-block:: console

          $ neutron queue-create --min 10 --max 1000 myqueue
   * - Associates a queue with a network.
     - .. code-block:: console

          $ neutron net-create network --queue_id QUEUE_ID
   * - Creates a default system queue.
     - .. code-block:: console

          $ neutron queue-create --default True --min 10 --max 2000 default
   * - Lists QoS queues.
     - .. code-block:: console

          $ neutron queue-list
   * - Deletes a QoS queue.
     - .. code-block:: console

          $ neutron queue-delete QUEUE_ID_OR_NAME

VMware NSX provider networks extension
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Provider networks can be implemented in different ways by the underlying
NSX platform.

The *FLAT* and *VLAN* network types use bridged transport connectors.
These network types enable the attachment of large number of ports. To
handle the increased scale, the NSX plug-in can back a single OpenStack
Network with a chain of NSX logical switches. You can specify the
maximum number of ports on each logical switch in this chain on the
``max_lp_per_bridged_ls`` parameter, which has a default value of 5,000.

The recommended value for this parameter varies with the NSX version
running in the back-end, as shown in the following table.

**Recommended values for max_lp_per_bridged_ls**

+---------------+---------------------+
| NSX version   | Recommended Value   |
+===============+=====================+
| 2.x           | 64                  |
+---------------+---------------------+
| 3.0.x         | 5,000               |
+---------------+---------------------+
| 3.1.x         | 5,000               |
+---------------+---------------------+
| 3.2.x         | 10,000              |
+---------------+---------------------+

In addition to these network types, the NSX plug-in also supports a
special *l3_ext* network type, which maps external networks to specific
NSX gateway services as discussed in the next section.

VMware NSX L3 extension
^^^^^^^^^^^^^^^^^^^^^^^

NSX exposes its L3 capabilities through gateway services which are
usually configured out of band from OpenStack. To use NSX with L3
capabilities, first create an L3 gateway service in the NSX Manager.
Next, in ``/etc/neutron/plugins/vmware/nsx.ini`` set
``default_l3_gw_service_uuid`` to this value. By default, routers are
mapped to this gateway service.

VMware NSX L3 extension operations
''''''''''''''''''''''''''''''''''

Create external network and map it to a specific NSX gateway service:

.. code-block:: console

   $ openstack network create public --external --provider-network-type l3_ext \
   --provider-physical-network L3_GATEWAY_SERVICE_UUID

Terminate traffic on a specific VLAN from a NSX gateway service:

.. code-block:: console

   $ openstack network create public --external --provider-network-type l3_ext \
   --provider-physical-network L3_GATEWAY_SERVICE_UUID --provider-segment VLAN_ID

Operational status synchronization in the VMware NSX plug-in
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Starting with the Havana release, the VMware NSX plug-in provides an
asynchronous mechanism for retrieving the operational status for neutron
resources from the NSX back-end; this applies to *network*, *port*, and
*router* resources.

The back-end is polled periodically and the status for every resource is
retrieved; then the status in the Networking database is updated only
for the resources for which a status change occurred. As operational
status is now retrieved asynchronously, performance for ``GET``
operations is consistently improved.

Data to retrieve from the back-end are divided in chunks in order to
avoid expensive API requests; this is achieved leveraging NSX APIs
response paging capabilities. The minimum chunk size can be specified
using a configuration option; the actual chunk size is then determined
dynamically according to: total number of resources to retrieve,
interval between two synchronization task runs, minimum delay between
two subsequent requests to the NSX back-end.

The operational status synchronization can be tuned or disabled using
the configuration options reported in this table; it is however worth
noting that the default values work fine in most cases.

.. list-table:: **Configuration options for tuning operational status synchronization in the NSX plug-in**
   :widths: 10 10 10 10 35
   :header-rows: 1

   * - Option name
     - Group
     - Default value
     - Type and constraints
     - Notes
   * - ``state_sync_interval``
     - ``nsx_sync``
     - 10 seconds
     - Integer; no constraint.
     - Interval in seconds between two run of the synchronization task. If the
       synchronization task takes more than ``state_sync_interval`` seconds to
       execute, a new instance of the task is started as soon as the other is
       completed. Setting the value for this option to 0 will disable the
       synchronization task.
   * - ``max_random_sync_delay``
     - ``nsx_sync``
     - 0 seconds
     - Integer. Must not exceed ``min_sync_req_delay``
     - When different from zero, a random delay between 0 and
       ``max_random_sync_delay`` will be added before processing the next
       chunk.
   * - ``min_sync_req_delay``
     - ``nsx_sync``
     - 1 second
     - Integer. Must not exceed ``state_sync_interval``.
     - The value of this option can be tuned according to the observed
       load on the NSX controllers. Lower values will result in faster
       synchronization, but might increase the load on the controller cluster.
   * - ``min_chunk_size``
     - ``nsx_sync``
     - 500 resources
     - Integer; no constraint.
     - Minimum number of resources to retrieve from the back-end for each
       synchronization chunk. The expected number of synchronization chunks
       is given by the ratio between ``state_sync_interval`` and
       ``min_sync_req_delay``. This size of a chunk might increase if the
       total number of resources is such that more than ``min_chunk_size``
       resources must be fetched in one chunk with the current number of
       chunks.
   * - ``always_read_status``
     - ``nsx_sync``
     - False
     - Boolean; no constraint.
     - When this option is enabled, the operational status will always be
       retrieved from the NSX back-end ad every ``GET`` request. In this
       case it is advisable to disable the synchronization task.

When running multiple OpenStack Networking server instances, the status
synchronization task should not run on every node; doing so sends
unnecessary traffic to the NSX back-end and performs unnecessary DB
operations. Set the ``state_sync_interval`` configuration option to a
non-zero value exclusively on a node designated for back-end status
synchronization.

The ``fields=status`` parameter in Networking API requests always
triggers an explicit query to the NSX back end, even when you enable
asynchronous state synchronization. For example, ``GET
/v2.0/networks/NET_ID?fields=status&fields=name``.

Big Switch plug-in extensions
-----------------------------

This section explains the Big Switch neutron plug-in-specific extension.

Big Switch router rules
^^^^^^^^^^^^^^^^^^^^^^^

Big Switch allows router rules to be added to each project router. These
rules can be used to enforce routing policies such as denying traffic
between subnets or traffic to external networks. By enforcing these at
the router level, network segmentation policies can be enforced across
many VMs that have differing security groups.

Router rule attributes
''''''''''''''''''''''

Each project router has a set of router rules associated with it. Each
router rule has the attributes in this table. Router rules and their
attributes can be set using the :command:`neutron router-update` command,
through the horizon interface or the Networking API.

.. list-table:: **Big Switch Router rule attributes**
   :widths: 10 10 10 35
   :header-rows: 1

   * - Attribute name
     - Required
     - Input type
     - Description
   * - source
     - Yes
     - A valid CIDR or one of the keywords 'any' or 'external'
     - The network that a packet's source IP must match for the
       rule to be applied.
   * - destination
     - Yes
     - A valid CIDR or one of the keywords 'any' or 'external'
     - The network that a packet's destination IP must match for the rule to
       be applied.
   * - action
     - Yes
     - 'permit' or 'deny'
     - Determines whether or not the matched packets will allowed to cross the
       router.
   * - nexthop
     - No
     - A plus-separated (+) list of next-hop IP addresses. For example,
       ``1.1.1.1+1.1.1.2``.
     - Overrides the default virtual router used to handle traffic for packets
       that match the rule.

Order of rule processing
''''''''''''''''''''''''

The order of router rules has no effect. Overlapping rules are evaluated
using longest prefix matching on the source and destination fields. The
source field is matched first so it always takes higher precedence over
the destination field. In other words, longest prefix matching is used
on the destination field only if there are multiple matching rules with
the same source.

Big Switch router rules operations
''''''''''''''''''''''''''''''''''

Router rules are configured with a router update operation in OpenStack
Networking. The update overrides any previous rules so all rules must be
provided at the same time.

Update a router with rules to permit traffic by default but block
traffic from external networks to the 10.10.10.0/24 subnet:

.. code-block:: console

   $ neutron router-update ROUTER_UUID --router_rules type=dict list=true \
     source=any,destination=any,action=permit \
     source=external,destination=10.10.10.0/24,action=deny

Specify alternate next-hop addresses for a specific subnet:

.. code-block:: console

   $ neutron router-update ROUTER_UUID --router_rules type=dict list=true  \
     source=any,destination=any,action=permit \
     source=10.10.10.0/24,destination=any,action=permit,nexthops=10.10.10.254+10.10.10.253

Block traffic between two subnets while allowing everything else:

.. code-block:: console

   $ neutron router-update ROUTER_UUID --router_rules type=dict list=true \
     source=any,destination=any,action=permit \
     source=10.10.10.0/24,destination=10.20.20.20/24,action=deny

L3 metering
~~~~~~~~~~~

The L3 metering API extension enables administrators to configure IP
ranges and assign a specified label to them to be able to measure
traffic that goes through a virtual router.

The L3 metering extension is decoupled from the technology that
implements the measurement. Two abstractions have been added: One is the
metering label that can contain metering rules. Because a metering label
is associated with a project, all virtual routers in this project are
associated with this label.

Basic L3 metering operations
----------------------------

Only administrators can manage the L3 metering labels and rules.

This table shows example :command:`neutron` commands that enable you to
complete basic L3 metering operations:

.. list-table:: **Basic L3 operations**
   :widths: 20 50
   :header-rows: 1

   * - Operation
     - Command
   * - Creates a metering label.
     - .. code-block:: console

          $ openstack network meter label create LABEL1 \
            --description "DESCRIPTION_LABEL1"
   * - Lists metering labels.
     - .. code-block:: console

          $ openstack network meter label list
   * - Shows information for a specified label.
     - .. code-block:: console

          $ openstack network meter label show LABEL_UUID
          $ openstack network meter label show LABEL1
   * - Deletes a metering label.
     - .. code-block:: console

          $ openstack network meter label delete LABEL_UUID
          $ openstack network meter label delete LABEL1
   * - Creates a metering rule.
     - .. code-block:: console

          $ openstack network meter label rule create LABEL_UUID \
            --remote-ip-prefix CIDR \
            --direction DIRECTION --exclude

       For example:

       .. code-block:: console

          $ openstack network meter label rule create label1 \
            --remote-ip-prefix 10.0.0.0/24 --direction ingress
          $ openstack network meter label rule create label1 \
            --remote-ip-prefix 20.0.0.0/24 --exclude

   * - Lists metering all label rules.
     - .. code-block:: console

          $ openstack network meter label rule list
   * - Shows information for a specified label rule.
     - .. code-block:: console

          $ openstack network meter label rule show RULE_UUID
   * - Deletes a metering label rule.
     - .. code-block:: console

          $ openstack network meter label rule delete RULE_UUID
   * - Lists the value of created metering label rules.
     - .. code-block:: console

          $ ceilometer sample-list -m SNMP_MEASUREMENT

       For example:

       .. code-block:: console

          $ ceilometer sample-list -m hardware.network.bandwidth.bytes
          $ ceilometer sample-list -m hardware.network.incoming.bytes
          $ ceilometer sample-list -m hardware.network.outgoing.bytes
          $ ceilometer sample-list -m hardware.network.outgoing.errors
