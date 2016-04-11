..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Open vSwitch Firewall Driver
============================

The OVS driver has the same API as the current iptables firewall driver,
keeping the state of security groups and ports inside of the firewall.
Class ``SGPortMap`` was created to keep state consistent, and maps from ports
to security groups and vice-versa. Every port and security group is represented
by its own object encapsulating the necessary information.

Note: Open vSwitch firewall driver uses register 5 for marking flow
related to port and register 6 which defines network and is used for conntrack
zones.


Firewall API calls
------------------

There are two main calls performed by the firewall driver in order to either
create or update a port with security groups - ``prepare_port_filter`` and
``update_port_filter``. Both methods rely on the security group objects that
are already defined in the driver and work similarly to their iptables
counterparts. The definition of the objects will be described later in this
document. ``prepare_port_filter`` must be called only once during port
creation, and it defines the initial rules for the port. When the port is
updated, all filtering rules are removed, and new rules are generated based on
the available information about security groups in the driver.

Security group rules can be defined in the firewall driver by calling
``update_security_group_rules``, which rewrites all the rules for a given
security group. If a remote security group is changed, then
``update_security_group_members`` is called to determine the set of IP
addresses that should be allowed for this remote security group. Calling this
method will not have any effect on existing instance ports. In other words, if
the port is using security groups and its rules are changed by calling one of
the above methods, then no new rules are generated for this port.
``update_port_filter`` must be called for the changes to take effect.

All the machinery above is controlled by security group RPC methods, which mean
the firewall driver doesn't have any logic of which port should be updated
based on the provided changes, it only accomplishes actions when called from
the controller.


OpenFlow rules
--------------

At first, every connection is split into ingress and egress processes based on
the input or output port respectively. Each port contains the initial
hardcoded flows for ARP, DHCP and established connections, which are accepted
by default. To detect established connections, a flow must by marked by
conntrack first with an ``action=ct()`` rule. An accepted flow means that
ingress packets for the connection are directly sent to the port, and egress
packets are left to be normally switched by the integration bridge.

Connections that are not matched by the above rules are sent to either the
ingress or egress filtering table, depending on its direction. The reason the
rules are based on security group rules in separate tables is to make it easy
to detect these rules during removal.

The firewall driver method ``create_rules_generator_for_port`` creates a
generator that builds a single security group rule either from rules belonging
to a given group, or rules allowing connections to remote groups. Every rule is
then expanded into several OpenFlow rules by the method
``create_flows_from_rule_and_port``.


Rules example with explanation:
-------------------------------

The following example presents two ports on the same host. They have different
security groups and there is icmp traffic allowed from first security group to
the second security group. Ports have following attributes:

::

 Port 1
   - plugged to the port 1 in OVS bridge
   - ip address: 192.168.0.1
   - mac address: fa:16:3e:a4:22:10
   - security group 1: can send icmp packets out

 Port 2
   - plugged to the port 2 in OVS bridge
   - ip address: 192.168.0.2
   - mac address: fa:16:3e:24:57:c7
   - security group 2: can receive icmp packets from security group 1

The first ``table 0`` distinguishes the traffic to ingress or egress and loads
to ``register 5`` value identifying port traffic.
Ingress flow is determined by switch port number and egress flow is determined
by destination mac address. ``register 6`` contains

::

 table=0,  priority=100,in_port=1 actions=load:0x1->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,71)
 table=0,  priority=100,in_port=2 actions=load:0x2->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,71)
 table=0,  priority=90,dl_dst=fa:16:3e:a4:22:10 actions=load:0x1->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,81)
 table=0,  priority=90,dl_dst=fa:16:3e:24:57:c7 actions=load:0x2->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,81)
 table=0,  priority=0 actions=NORMAL

Following ``table 71`` implements arp spoofing protection, ip spoofing
protection, allows traffic for obtaining ip addresses (dhcp, dhcpv6, slaac,
ndp) for egress traffic and allows arp replies. Also identifies not tracked
connections which are processed later with information obtained from
conntrack. Notice the ``zone=NXM_NX_REG6[0..15]`` in ``actions`` when obtaining
information from conntrack. It says every port has its own conntrack zone
defined by value in ``register 6``. It's there to avoid accepting established
traffic that belongs to different port with same conntrack parameters.

Rules below allow ICMPv6 traffic for multicast listeners, neighbour
solicitation and neighbour advertisement.

::

 table=71, priority=95,icmp6,reg5=0x1,in_port=1,icmp_type=130 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x1,in_port=1,icmp_type=131 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x1,in_port=1,icmp_type=132 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x1,in_port=1,icmp_type=135 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x1,in_port=1,icmp_type=136 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,icmp_type=130 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,icmp_type=131 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,icmp_type=132 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,icmp_type=135 actions=NORMAL
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,icmp_type=136 actions=NORMAL

Following rules implement arp spoofing protection

::

 table=71, priority=95,arp,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:10,arp_spa=192.168.0.1 actions=NORMAL
 table=71, priority=95,arp,reg5=0x2,in_port=2,dl_src=fa:16:3e:24:57:c7,arp_spa=192.168.0.2 actions=NORMAL

DHCP and DHCPv6 traffic is allowed to instance but DHCP servers are blocked on
instances.

::

 table=71, priority=80,udp,reg5=0x1,in_port=1,tp_src=68,tp_dst=67 actions=resubmit(,73)
 table=71, priority=80,udp6,reg5=0x1,in_port=1,tp_src=546,tp_dst=547 actions=resubmit(,73)
 table=71, priority=70,udp,reg5=0x1,in_port=1,tp_src=67,tp_dst=68 actions=drop
 table=71, priority=70,udp6,reg5=0x1,in_port=1,tp_src=547,tp_dst=546 actions=drop
 table=71, priority=80,udp,reg5=0x2,in_port=2,tp_src=68,tp_dst=67 actions=resubmit(,73)
 table=71, priority=80,udp6,reg5=0x2,in_port=2,tp_src=546,tp_dst=547 actions=resubmit(,73)
 table=71, priority=70,udp,reg5=0x2,in_port=2,tp_src=67,tp_dst=68 actions=drop
 table=71, priority=70,udp6,reg5=0x2,in_port=2,tp_src=547,tp_dst=546 actions=drop

Flowing rules obtain conntrack information for valid ip and mac address
combinations. All other packets are dropped.

::

 table=71, priority=65,ct_state=-trk,ip,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:10,nw_src=192.168.0.1 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=65,ct_state=-trk,ip,reg5=0x2,in_port=2,dl_src=fa:16:3e:24:57:c7,nw_src=192.168.0.2 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=65,ct_state=-trk,ipv6,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:10,ipv6_src=fe80::f816:3eff:fea4:2210 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=65,ct_state=-trk,ipv6,reg5=0x2,in_port=2,dl_src=fa:16:3e:24:57:c7,ipv6_src=fe80::f816:3eff:fe24:57c7 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=10,ct_state=-trk,reg5=0x1,in_port=1 actions=drop
 table=71, priority=10,ct_state=-trk,reg5=0x2,in_port=2 actions=drop
 table=71, priority=0 actions=drop


``table 72`` accepts only established or related connections, and implements
rules defined by the security group. As this egress connection might also be an
ingress connection for some other port, it's not switched yet but eventually
processed by ingress pipeline.

All established or new connections defined by security group rule are
``accepted``, which will be explained later. All invalid packets are dropped.
In case below we allow all icmp egress traffic.

::

 table=72, priority=70,ct_state=+est-rel-rpl,icmp,reg5=0x1,dl_src=fa:16:3e:a4:22:10 actions=resubmit(,73)
 table=72, priority=70,ct_state=+new-est,icmp,reg5=0x1,dl_src=fa:16:3e:a4:22:10 actions=resubmit(,73)
 table=72, priority=50,ct_state=+inv+trk actions=drop


Important on the flows below is the ``ct_mark=0x1``. Such value have flows that
were marked as not existing anymore by rule introduced later. Those are
typically connections that were allowed by some security group rule and the
rule was removed.

::

 table=72, priority=50,ct_mark=0x1,reg5=0x1 actions=drop
 table=72, priority=50,ct_mark=0x1,reg5=0x2 actions=drop

All other connections that are not marked and are established or related are
allowed.

::

 table=72, priority=50,ct_state=+est-rel+rpl,ct_zone=644,ct_mark=0,reg5=0x1 actions=NORMAL
 table=72, priority=50,ct_state=+est-rel+rpl,ct_zone=644,ct_mark=0,reg5=0x2 actions=NORMAL
 table=72, priority=50,ct_state=-new-est+rel-inv,ct_zone=644,ct_mark=0,reg5=0x1 actions=NORMAL
 table=72, priority=50,ct_state=-new-est+rel-inv,ct_zone=644,ct_mark=0,reg5=0x2 actions=NORMAL

In the following flows are marked established connections that weren't matched
in the previous flows, which means they don't have accepting security group
rule anymore.

::

 table=72, priority=40,ct_state=-est,reg5=0x1 actions=drop
 table=72, priority=40,ct_state=+est,reg5=0x1 actions=ct(commit,zone=NXM_NX_REG6[0..15],exec(load:0x1->NXM_NX_CT_MARK[]))
 table=72, priority=40,ct_state=-est,reg5=0x2 actions=drop
 table=72, priority=40,ct_state=+est,reg5=0x2 actions=ct(commit,zone=NXM_NX_REG6[0..15],exec(load:0x1->NXM_NX_CT_MARK[]))
 table=72, priority=0 actions=drop

In following ``table 73`` are all detected ingress connections sent to ingress
pipeline. Since the connection was already accepted by egress pipeline, all
remaining egress connections are sent to normal switching.

::

 table=73, priority=100,dl_dst=fa:16:3e:a4:22:10 actions=load:0x1->NXM_NX_REG5[],resubmit(,81)
 table=73, priority=100,dl_dst=fa:16:3e:24:57:c7 actions=load:0x2->NXM_NX_REG5[],resubmit(,81)
 table=73, priority=90,ct_state=+new-est,reg5=0x1 actions=ct(commit,zone=NXM_NX_REG6[0..15]),NORMAL
 table=73, priority=90,ct_state=+new-est,reg5=0x2 actions=ct(commit,zone=NXM_NX_REG6[0..15]),NORMAL
 table=73, priority=80,reg5=0x1 actions=NORMAL
 table=73, priority=80,reg5=0x2 actions=NORMAL
 table=73, priority=0 actions=drop

``table 81`` is similar to ``table 71``, allows basic ingress traffic for
obtaining ip address and arp queries. Note that vlan tag must be removed by
adding ``strip_vlan`` to actions list, prior to injecting packet directly to
port. Not tracked packets are sent to obtain conntrack information.

::

 table=81, priority=100,arp,reg5=0x1,dl_dst=fa:16:3e:a4:22:10 actions=strip_vlan,output:1
 table=81, priority=100,arp,reg5=0x2,dl_dst=fa:16:3e:24:57:c7 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x1,dl_dst=fa:16:3e:a4:22:10,icmp_type=130 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x1,dl_dst=fa:16:3e:a4:22:10,icmp_type=131 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x1,dl_dst=fa:16:3e:a4:22:10,icmp_type=132 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x1,dl_dst=fa:16:3e:a4:22:10,icmp_type=135 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x1,dl_dst=fa:16:3e:a4:22:10,icmp_type=136 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x2,dl_dst=fa:16:3e:24:57:c7,icmp_type=130 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x2,dl_dst=fa:16:3e:24:57:c7,icmp_type=131 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x2,dl_dst=fa:16:3e:24:57:c7,icmp_type=132 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x2,dl_dst=fa:16:3e:24:57:c7,icmp_type=135 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x2,dl_dst=fa:16:3e:24:57:c7,icmp_type=136 actions=strip_vlan,output:2
 table=81, priority=95,udp,reg5=0x1,tp_src=67,tp_dst=68 actions=strip_vlan,output:1
 table=81, priority=95,udp6,reg5=0x1,tp_src=547,tp_dst=546 actions=strip_vlan,output:1
 table=81, priority=95,udp,reg5=0x2,tp_src=67,tp_dst=68 actions=strip_vlan,output:2
 table=81, priority=95,udp6,reg5=0x2,tp_src=547,tp_dst=546 actions=strip_vlan,output:2
 table=81, priority=90,ct_state=-trk,ip,reg5=0x1 actions=ct(table=82,zone=NXM_NX_REG6[0..15])
 table=81, priority=90,ct_state=-trk,ipv6,reg5=0x1 actions=ct(table=82,zone=NXM_NX_REG6[0..15])
 table=81, priority=90,ct_state=-trk,ip,reg5=0x2 actions=ct(table=82,zone=NXM_NX_REG6[0..15])
 table=81, priority=90,ct_state=-trk,ipv6,reg5=0x2 actions=ct(table=82,zone=NXM_NX_REG6[0..15])
 table=81, priority=80,ct_state=+trk,reg5=0x1,dl_dst=fa:16:3e:a4:22:10 actions=resubmit(,82)
 table=81, priority=80,ct_state=+trk,reg5=0x2,dl_dst=fa:16:3e:24:57:c7 actions=resubmit(,82)
 table=81, priority=0 actions=drop

Similarly to ``table 72``, ``table 82`` accepts established and related
connections. In this case we allow all icmp traffic coming from
``security group 1`` which is in this case only ``port 1`` with ip address
``192.168.0.1``.

::

 table=82, priority=70,ct_state=+est-rel-rpl,icmp,reg5=0x2,dl_dst=fa:16:3e:24:57:c7,nw_src=192.168.0.1 actions=strip_vlan,output:2
 table=82, priority=70,ct_state=+new-est,icmp,reg5=0x2,dl_dst=fa:16:3e:24:57:c7,nw_src=192.168.0.1 actions=ct(commit,zone=NXM_NX_REG6[0..15]),strip_vlan,output:2
 table=82, priority=50,ct_state=+inv+trk actions=drop

The mechanism for dropping connections that are not allowed anymore is the
same as in ``table 72``.

::

 table=82, priority=50,ct_mark=0x1,reg5=0x1 actions=drop
 table=82, priority=50,ct_mark=0x1,reg5=0x2 actions=drop
 table=82, priority=50,ct_state=+est-rel+rpl,ct_zone=644,ct_mark=0,reg5=0x1,dl_dst=fa:16:3e:a4:22:10 actions=strip_vlan,output:1
 table=82, priority=50,ct_state=+est-rel+rpl,ct_zone=644,ct_mark=0,reg5=0x2,dl_dst=fa:16:3e:24:57:c7 actions=strip_vlan,output:2
 table=82, priority=50,ct_state=-new-est+rel-inv,ct_zone=644,ct_mark=0,reg5=0x1,dl_dst=fa:16:3e:a4:22:10 actions=strip_vlan,output:1
 table=82, priority=50,ct_state=-new-est+rel-inv,ct_zone=644,ct_mark=0,reg5=0x2,dl_dst=fa:16:3e:24:57:c7 actions=strip_vlan,output:2
 table=82, priority=40,ct_state=-est,reg5=0x1 actions=drop
 table=82, priority=40,ct_state=+est,reg5=0x1 actions=ct(commit,zone=NXM_NX_REG6[0..15],exec(load:0x1->NXM_NX_CT_MARK[]))
 table=82, priority=40,ct_state=-est,reg5=0x2 actions=drop
 table=82, priority=40,ct_state=+est,reg5=0x2 actions=ct(commit,zone=NXM_NX_REG6[0..15],exec(load:0x1->NXM_NX_CT_MARK[]))
 table=82, priority=0 actions=drop


Note: Conntrack zones on a single node are now based on network to which port is
plugged in. That makes a difference between traffic on hypervisor only and
east-west traffic. For example, if port has a VIP that was migrated to a port on
different node, then new port won't contain conntrack information about previous
traffic that happened with VIP.


Future work
-----------

 - Create fullstack tests with tunneling enabled
 - Conjunctions in Openflow rules can be created to decrease the number of
   rules needed for remote security groups
 - During the update of firewall rules, we can use bundles to make the changes
   atomic


Upgrade path from iptables hybrid driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

During an upgrade, the agent will need to re-plug each instance's tap device
into the integration bridge while trying to not break existing connections. One
of the following approaches can be taken:

1) Pause the running instance in order to prevent a short period of time where
its network interface does not have firewall rules. This can happen due to
the firewall driver calling OVS to obtain information about OVS the port. Once
the instance is paused and no traffic is flowing, we can delete the qvo
interface from integration bridge, detach the tap device from the qbr bridge
and plug the tap device back into the integration bridge. Once this is done,
the firewall rules are applied for the OVS tap interface and the instance is
started from its paused state.

2) Set drop rules for the instance's tap interface, delete the qbr bridge and
related veths, plug the tap device into the integration bridge, apply the OVS
firewall rules and finally remove the drop rules for the instance.

3) Compute nodes can be upgraded one at a time. A free node can be switched to
use the OVS firewall, and instances from other nodes can be live-migrated to
it. Once the first node is evacuated, its firewall driver can be then be
switched to the OVS driver.
