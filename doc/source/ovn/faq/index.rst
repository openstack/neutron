.. _ovn_faq:

==========================
Frequently Asked Questions
==========================

**Q: What are the key differences between ML2/ovs and ML2/ovn?**

+---------------+---------------------------+--------------------------------+
| Detail        | ml2/ovs                   | ml2/ovn                        |
+===============+===========================+================================+
| agent/server  | rabbit mq messaging + RPC.| ovsdb protocol on the          |
| communication |                           | NorthBound and SouthBound      |
|               |                           | databases.                     |
+---------------+---------------------------+--------------------------------+
| l3ha          | routers expose an "ha"    | routers don't expose an "ha"   |
| API           | field that can be disabled| field, and will make use of HA |
|               | or enabled by admin with a| as soon as there is more than  |
|               | deployment default.       | one network node available.    |
+---------------+---------------------------+--------------------------------+
| l3ha          | qrouter namespace with    | ovn-controller configures      |
| dataplane     | keepalive process and an  | specific OpenFlow rules, and   |
|               | internal ha network for   | enables BFD protocol over      |
|               | VRRP traffic.             | tunnel endpoints to detect     |
|               |                           | connectivity issues to nodes.  |
+---------------+---------------------------+--------------------------------+
| DVR           | exposes the "distributed" | exposes the "distributed" flag |
| API           | flag on routers only      | based on the configuration     |
|               | modifiable by admin.      | option                         |
|               |                           | enable_distributed_floating_ip |
+---------------+---------------------------+--------------------------------+
| DVR           | uses namespaces, veths,   | Uses OpenFlow rules on the     |
| dataplane     | ip routing, ip rules and  | compute nodes.                 |
|               | iptables on the compute   |                                |
|               | nodes.                    |                                |
+---------------+---------------------------+--------------------------------+
| E/W traffic   | goes through network nodes| completely distributed in      |
|               | when the router is not    | all cases.                     |
|               | distributed (DVR).        |                                |
+---------------+---------------------------+--------------------------------+
| Metadata      | Metadata service is       | Metadata is completely         |
| Service       | provided by the qrouters  | distributed across compute     |
|               | or dhcp namespaces in the | nodes, and served from the     |
|               | network nodes.            | ovnmeta-xxxxx-xxxx namespace.  |
+---------------+---------------------------+--------------------------------+
| DHCP          | DHCP is provided via      | DHCP is provided by OpenFlow   |
| Service       | qdhcp-xxxxx-xxx namespaces| and ovn-controller, being      |
|               | which run dnsmasq inside. | distributed across computes.   |
+---------------+---------------------------+--------------------------------+
| Trunk         | Trunk ports are built     | Trunk ports live in br-int     |
| Ports         | by creating br-trunk-xxx  | as OpenFlow rules, while       |
|               | bridges and patch ports.  | subports are directly attached |
|               |                           | to br-int.                     |
+---------------+---------------------------+--------------------------------+

**Q: Why can't I use the distributed or ha flags of routers?**

Networking OVN implements HA and distributed in a transparent way for the
administrator and users.

HA will be automatically used on routers as soon as more than two
gateway nodes are detected. And distributed floating IPs will be used
as soon as it's configured (see next question).

**Q: Does OVN support DVR or distributed L3 routing?**

Yes, it's controlled by a single flag in configuration.

DVR will be used for floating IPs if the ovn / enable_distributed_floating_ip
flag is configured to True in the neutron server configuration, being
a deployment wide setting. In contrast to ML2/ovs which was able to specify
this setting per router (only admin).

Although ovn driver does not expose the "distributed" flag of routers
throught the API.

**Q: Does OVN support integration with physical switches?**

OVN currently integrates with physical switches by optionally using them as
VTEP gateways from logical to physical networks and via integrations provided
by the Neutron ML2 framework, hierarchical port binding.

**Q: What's the status of HA for ovn driver and OVN?**

Typically, multiple copies of neutron-server are run across multiple servers
and uses a load balancer.  The neutron ML2 mechanism driver provided by
ovn driver supports this deployment model. DHCP and metadata services
are distributed across compute nodes, and don't depend on the network nodes.

The network controller portion of OVN is distributed - an instance of the
ovn-controller service runs on every hypervisor.  OVN also includes some
central components for control purposes.

ovn-northd is a centralized service that does some translation between the
northbound and southbound databases in OVN.  Currently, you only run this
service once.  You can manage it in an active/passive HA mode using something
like Pacemaker.  The OVN project plans to allow this service to be horizontally
scaled both for scaling and HA reasons.  This will allow it to be run in an
active/active HA mode.

OVN also makes use of ovsdb-server for the OVN northbound and southbound
databases.  ovsdb-server supports active/passive HA using replication.
For more information, see:
http://docs.openvswitch.org/en/latest/topics/ovsdb-replication/

A typical deployment would use something like Pacemaker to manage the
active/passive HA process.  Clients would be pointed at a virtual IP
address.  When the HA manager detects a failure of the master, the
virtual IP would be moved and the passive replica would become the
new master.

**Q: Which core OVN version should I use for my OpenStack installation?**

OpenStack doesn't set explicit version requirements for OVN installation, but
it's recommended to follow at least the version that is used in upstream CI,
e.g.:
https://github.com/openstack/neutron/blob/4d31284373e89cb2b29539d6718f90a4c4d8284b/zuul.d/tempest-singlenode.yaml#L310

Some new features may require the latest core OVN version to work. For example,
to be able to use VXLAN network type, one must run OVN 20.09+.

See :doc:`/admin/ovn/ovn` for links to more details on OVN's architecture.
