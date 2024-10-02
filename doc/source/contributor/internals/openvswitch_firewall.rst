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

.. note::

  Open vSwitch firewall driver uses ``register 5`` for identifying the port
  related to the flow and ``register 6`` which identifies the network, used
  in particular for conntrack zones.

Ingress/Egress Terminology
--------------------------

In this document, the terms ``ingress`` and ``egress`` are relative to
a VM instance connected to OVS (or a netns connected to OVS):

* ``ingress`` applies to traffic that will ultimately go into a VM (or into
  a netns), assuming it is not dropped

* ``egress`` applies to traffic coming from a VM (or from a netns)

::

                    .                                     .
             _______|\                             _______|\
            \ ingress \                           \ ingress \
            /_______  /                           /_______  /
                    |/        .-----------------.         |/
                    '         |                 |         '
                              |                 |-----------( netns interface )
  ( non-VM, non-netns     )---|       OVS       |
  ( interface: phy, patch )   |                 |------------( VM interface )
              .               |                 |   .
             /|________       '-----------------'  /|________
            /   egress /                          /   egress /
            \  ________\                          \  ________\
             \|                                    \|
              '                                     '

Note that these terms are used differently in OVS code and documentation, where
they are relative to the OVS bridge, with ``ingress`` applying to traffic as
it comes into the OVS bridge, and ``egress`` applying to traffic as it leaves
the OVS bridge.

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

.. note::

  There is a new config option ``explicitly_egress_direct``, if it is set
  to True, it will direct egress unicast traffic to the local port directly
  or to the patch bridge port if the destination is in a remote host. So there
  is no NORMAL for egress in such scenario. This option is used to overcome
  the egress packet flooding when the openflow firewall is enabled.

Connections that are not matched by the above rules are sent to either the
ingress or egress filtering table, depending on its direction. The reason the
rules are based on security group rules in separate tables is to make it easy
to detect these rules during removal.

Security group rules are treated differently for those without a
remote group ID and those with a remote group ID. A security group
rule without a remote group ID is expanded into several OpenFlow rules
by the method ``create_flows_from_rule_and_port``.  A security group
rule with a remote group ID is expressed by three sets of flows. The
first two are conjunctive flows which will be described in the next
section.  The third set matches on the conjunction IDs and does accept
actions.


Flow priorities for security group rules
----------------------------------------

The OpenFlow spec says a packet should not match against multiple
flows at the same priority [1]_. The firewall driver uses 8 levels of
priorities to achieve this. The method ``flow_priority_offset``
calculates a priority for a given security group rule.  The use of
priorities is essential with conjunction flows, which will be
described later in the conjunction flows examples.

.. [1] Although OVS seems to magically handle overlapping flows under
   some cases, we shouldn't rely on that.


Uses of conjunctive flows
-------------------------

With a security group rule with a remote group ID, flows that match on
nw_src for remote_group_id addresses and match on dl_dst for port MAC
addresses are needed (for ingress rules; likewise for egress
rules). Without conjunction, this results in O(n*m) flows where n and
m are number of ports in the remote group ID and the port security group,
respectively.

A conj_id is allocated for each (remote_group_id, security_group_id,
direction, ethertype, flow_priority_offset) tuple.  The class
``ConjIdMap`` handles the mapping. The same conj_id is shared between
security group rules if multiple rules belong to the same tuple above.

Conjunctive flows consist of 2 dimensions. Flows that belong to the
dimension 1 of 2 are generated by the method
``create_flows_for_ip_address`` and are in charge of IP address based
filtering specified by their remote group IDs. Flows that belong to
the dimension 2 of 2 are generated by the method
``create_flows_from_rule_and_port`` and modified by the method
``substitute_conjunction_actions``, which represents the portion of
the rule other than its remote group ID.

Those dimension 2 of 2 flows are per port and contain no remote group
information.  When there are multiple security group rules for a port,
those flows can overlap. To avoid such a situation, flows are sorted
and fed to ``merge_port_ranges`` or ``merge_common_rules`` methods to
rearrange them.


Rules example with explanation:
-------------------------------

The following example presents two ports on the same host. They have different
security groups and there is ICMP traffic allowed from the first security group
to the second security group. Ports have the following attributes:

::

 Port 1
   - plugged to the port 1 in OVS bridge
   - IP address: 192.168.0.1
   - MAC address: fa:16:3e:a4:22:10
   - security group 1: can send ICMP packets out
   - allowed address pair: 10.0.0.1/32, fa:16:3e:8c:84:13

 Port 2
   - plugged to the port 2 in OVS bridge
   - IP address: 192.168.0.2
   - MAC address: fa:16:3e:24:57:c7
   - security group 2:
      - can receive ICMP packets from security group 1
      - can receive TCP packets from security group 1
      - can receive TCP packets to port 80 from security group 2
      - can receive IP packets from security group 3
   - allowed address pair: 10.1.0.0/24, fa:16:3e:8c:84:14

 Port 3
   - patch bridge port (e.g. patch-tun) in OVS bridge

|table_0| - |table_59| contain some low priority rules to continue packet
processing in |table_60| aka TRANSIENT table. |table_0| - |table_59| is
left for use to other features that take precedence over firewall, e.g.
DVR, ARP poison/spoofing prevention, MAC spoof filtering and packet rate
limitation etc. The only requirement is
that after such a feature is done with its processing, it needs to pass packets
for processing to the TRANSIENT table. This TRANSIENT table distinguishes the
ingress traffic from the egress traffic and loads into ``register 5`` a value
identifying the port (for egress traffic based on the switch port number, and
for ingress traffic based on the network id and destination MAC address);
``register 6`` contains a value identifying the network (which is also the
OVSDB port tag) to isolate connections into separate conntrack zones.
For VLAN networks, the physical VLAN tag will be used to act as an extra
match rule to do such identifying work as well.

::

 table=60,  priority=100,in_port=1 actions=load:0x1->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,71)
 table=60,  priority=100,in_port=2 actions=load:0x2->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,71)
 table=60,  priority=90,dl_vlan=0x284,dl_dst=fa:16:3e:a4:22:10 actions=load:0x1->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,81)
 table=60,  priority=90,dl_vlan=0x284,dl_dst=fa:16:3e:8c:84:13 actions=load:0x1->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,81)
 table=60,  priority=90,dl_vlan=0x284,dl_dst=fa:16:3e:24:57:c7 actions=load:0x2->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,81)
 table=60,  priority=90,dl_vlan=0x284,dl_dst=fa:16:3e:8c:84:14 actions=load:0x2->NXM_NX_REG5[],load:0x284->NXM_NX_REG6[],resubmit(,81)
 table=60,  priority=0 actions=NORMAL

The following table, |table_71| implements ARP spoofing protection, IP spoofing
protection, allows traffic related to IP address allocations (DHCP, DHCPv6,
SLAAC, NDP) for egress traffic, and allows ARP replies. Also identifies not
tracked connections which are processed later with information obtained from
conntrack. Notice the ``zone=NXM_NX_REG6[0..15]`` in ``actions`` when obtaining
information from conntrack. It says every port has its own conntrack zone
defined by the value in ``register 6`` (OVSDB port tag identifying the
network). It's there to avoid accepting established traffic that belongs to a
different port with the same conntrack parameters.

The very first rule in |table_71| is a rule removing conntrack information for
a use-case where a Neutron logical port is placed directly to the hypervisor.
In such cases the kernel does conntrack lookup before the packet reaches the
Open vSwitch bridge. Tracked packets are sent back for processing by the same
table after conntrack information is cleared.

::

 table=71, priority=110,ct_state=+trk actions=ct_clear,resubmit(,71)

Rules below allow ICMPv6 traffic for multicast listeners, neighbour
solicitation and neighbour advertisement.

::

 table=71, priority=95,icmp6,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:11,ipv6_src=fe80::11,icmp_type=130 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:11,ipv6_src=fe80::11,icmp_type=131 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:11,ipv6_src=fe80::11,icmp_type=132 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:11,ipv6_src=fe80::11,icmp_type=135 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:11,ipv6_src=fe80::11,icmp_type=136 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,dl_src=fa:16:3e:a4:22:22,ipv6_src=fe80::22,icmp_type=130 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,dl_src=fa:16:3e:a4:22:22,ipv6_src=fe80::22,icmp_type=131 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,dl_src=fa:16:3e:a4:22:22,ipv6_src=fe80::22,icmp_type=132 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,dl_src=fa:16:3e:a4:22:22,ipv6_src=fe80::22,icmp_type=135 actions=resubmit(,94)
 table=71, priority=95,icmp6,reg5=0x2,in_port=2,dl_src=fa:16:3e:a4:22:22,ipv6_src=fe80::22,icmp_type=136 actions=resubmit(,94)

Following rules implement ARP spoofing protection

::

 table=71, priority=95,arp,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:10,arp_spa=192.168.0.1 actions=resubmit(,94)
 table=71, priority=95,arp,reg5=0x1,in_port=1,dl_src=fa:16:3e:8c:84:13,arp_spa=10.0.0.1 actions=resubmit(,94)
 table=71, priority=95,arp,reg5=0x2,in_port=2,dl_src=fa:16:3e:24:57:c7,arp_spa=192.168.0.2 actions=resubmit(,94)
 table=71, priority=95,arp,reg5=0x2,in_port=2,dl_src=fa:16:3e:8c:84:14,arp_spa=10.1.0.0/24 actions=resubmit(,94)

DHCP and DHCPv6 traffic is allowed to instance but DHCP servers are blocked on
instances.

::

 table=71, priority=80,udp,reg5=0x1,in_port=1,tp_src=68,tp_dst=67 actions=resubmit(,73)
 table=71, priority=80,udp6,reg5=0x1,in_port=1,tp_src=546,tp_dst=547 actions=resubmit(,73)
 table=71, priority=70,udp,reg5=0x1,in_port=1,tp_src=67,tp_dst=68 actions=resubmit(,93)
 table=71, priority=70,udp6,reg5=0x1,in_port=1,tp_src=547,tp_dst=546 actions=resubmit(,93)
 table=71, priority=80,udp,reg5=0x2,in_port=2,tp_src=68,tp_dst=67 actions=resubmit(,73)
 table=71, priority=80,udp6,reg5=0x2,in_port=2,tp_src=546,tp_dst=547 actions=resubmit(,73)
 table=71, priority=70,udp,reg5=0x2,in_port=2,tp_src=67,tp_dst=68 actions=resubmit(,93)
 table=71, priority=70,udp6,reg5=0x2,in_port=2,tp_src=547,tp_dst=546 actions=resubmit(,93)

Following rules obtain conntrack information for valid IP and MAC address
combinations. All other packets are dropped.

::

 table=71, priority=65,ip,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:10,nw_src=192.168.0.1 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=65,ip,reg5=0x1,in_port=1,dl_src=fa:16:3e:8c:84:13,nw_src=10.0.0.1 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=65,ip,reg5=0x2,in_port=2,dl_src=fa:16:3e:24:57:c7,nw_src=192.168.0.2 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=65,ip,reg5=0x2,in_port=2,dl_src=fa:16:3e:8c:84:14,nw_src=10.1.0.0/24 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=65,ipv6,reg5=0x1,in_port=1,dl_src=fa:16:3e:a4:22:10,ipv6_src=fe80::f816:3eff:fea4:2210 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=65,ipv6,reg5=0x2,in_port=2,dl_src=fa:16:3e:24:57:c7,ipv6_src=fe80::f816:3eff:fe24:57c7 actions=ct(table=72,zone=NXM_NX_REG6[0..15])
 table=71, priority=10,reg5=0x1,in_port=1 actions=resubmit(,93)
 table=71, priority=10,reg5=0x2,in_port=2 actions=resubmit(,93)
 table=71, priority=0 actions=drop


|table_72| accepts only established or related connections, and implements
rules defined by security groups. As this egress connection might also be an
ingress connection for some other port, it's not switched yet but eventually
processed by the ingress pipeline.

All established or new connections defined by security group rules are
``accepted``, which will be explained later. All invalid packets are dropped.
In the case below we allow all ICMP egress traffic.

::

 table=72, priority=75,ct_state=+est-rel-rpl,icmp,reg5=0x1 actions=resubmit(,73)
 table=72, priority=75,ct_state=+new-est,icmp,reg5=0x1 actions=resubmit(,73)
 table=72, priority=50,ct_state=+inv+trk actions=resubmit(,93)


Important on the flows below is the ``ct_mark=0x1``. Flows that
were marked as not existing anymore by rule introduced later will value this
value. Those are typically connections that were allowed by some security group
rule and the rule was removed.

::

 table=72, priority=50,ct_mark=0x1,reg5=0x1 actions=resubmit(,93)
 table=72, priority=50,ct_mark=0x1,reg5=0x2 actions=resubmit(,93)

All other connections that are not marked and are established or related are
allowed.

::

 table=72, priority=50,ct_state=+est-rel+rpl,ct_zone=644,ct_mark=0,reg5=0x1 actions=resubmit(,94)
 table=72, priority=50,ct_state=+est-rel+rpl,ct_zone=644,ct_mark=0,reg5=0x2 actions=resubmit(,94)
 table=72, priority=50,ct_state=-new-est+rel-inv,ct_zone=644,ct_mark=0,reg5=0x1 actions=resubmit(,94)
 table=72, priority=50,ct_state=-new-est+rel-inv,ct_zone=644,ct_mark=0,reg5=0x2 actions=resubmit(,94)

In the following, flows are marked established for connections that weren't
matched in the previous flows, which means they don't have an accepting
security group rule anymore.

::

 table=72, priority=40,ct_state=-est,reg5=0x1 actions=resubmit(,93)
 table=72, priority=40,ct_state=+est,reg5=0x1 actions=ct(commit,zone=NXM_NX_REG6[0..15],exec(load:0x1->NXM_NX_CT_MARK[]))
 table=72, priority=40,ct_state=-est,reg5=0x2 actions=resubmit(,93)
 table=72, priority=40,ct_state=+est,reg5=0x2 actions=ct(commit,zone=NXM_NX_REG6[0..15],exec(load:0x1->NXM_NX_CT_MARK[]))
 table=72, priority=0 actions=drop

In the following |table_73| are all detected ingress connections sent to the
ingress pipeline. Since the connection was already accepted by the egress
pipeline, all remaining egress connections are sent to the normal flood'n'learn
switching in |table_94|.

::

 table=73, priority=100,reg6=0x284,dl_dst=fa:16:3e:a4:22:10 actions=load:0x1->NXM_NX_REG5[],resubmit(,81)
 table=73, priority=100,reg6=0x284,dl_dst=fa:16:3e:8c:84:13 actions=load:0x1->NXM_NX_REG5[],resubmit(,81)
 table=73, priority=100,reg6=0x284,dl_dst=fa:16:3e:24:57:c7 actions=load:0x2->NXM_NX_REG5[],resubmit(,81)
 table=73, priority=100,reg6=0x284,dl_dst=fa:16:3e:8c:84:14 actions=load:0x2->NXM_NX_REG5[],resubmit(,81)
 table=73, priority=90,ct_state=+new-est,reg5=0x1 actions=ct(commit,zone=NXM_NX_REG6[0..15]),resubmit(,91)
 table=73, priority=90,ct_state=+new-est,reg5=0x2 actions=ct(commit,zone=NXM_NX_REG6[0..15]),resubmit(,91)
 table=73, priority=80,reg5=0x1 actions=resubmit(,94)
 table=73, priority=80,reg5=0x2 actions=resubmit(,94)
 table=73, priority=0 actions=drop

|table_81| is similar to |table_71|, allows basic ingress traffic for
obtaining IP address and ARP queries. Note that the VLAN tag must be removed by
adding ``strip_vlan`` to actions list, prior to injecting packet directly to
port. Not tracked packets are sent to obtain conntrack information.

::

 table=81, priority=100,arp,reg5=0x1 actions=strip_vlan,output:1
 table=81, priority=100,arp,reg5=0x2 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x1,icmp_type=130 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x1,icmp_type=131 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x1,icmp_type=132 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x1,icmp_type=135 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x1,icmp_type=136 actions=strip_vlan,output:1
 table=81, priority=100,icmp6,reg5=0x2,icmp_type=130 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x2,icmp_type=131 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x2,icmp_type=132 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x2,icmp_type=135 actions=strip_vlan,output:2
 table=81, priority=100,icmp6,reg5=0x2,icmp_type=136 actions=strip_vlan,output:2
 table=81, priority=95,udp,reg5=0x1,tp_src=67,tp_dst=68 actions=strip_vlan,output:1
 table=81, priority=95,udp6,reg5=0x1,tp_src=547,tp_dst=546 actions=strip_vlan,output:1
 table=81, priority=95,udp,reg5=0x2,tp_src=67,tp_dst=68 actions=strip_vlan,output:2
 table=81, priority=95,udp6,reg5=0x2,tp_src=547,tp_dst=546 actions=strip_vlan,output:2
 table=81, priority=90,ct_state=-trk,ip,reg5=0x1 actions=ct(table=82,zone=NXM_NX_REG6[0..15])
 table=81, priority=90,ct_state=-trk,ipv6,reg5=0x1 actions=ct(table=82,zone=NXM_NX_REG6[0..15])
 table=81, priority=90,ct_state=-trk,ip,reg5=0x2 actions=ct(table=82,zone=NXM_NX_REG6[0..15])
 table=81, priority=90,ct_state=-trk,ipv6,reg5=0x2 actions=ct(table=82,zone=NXM_NX_REG6[0..15])
 table=81, priority=80,ct_state=+trk,reg5=0x1 actions=resubmit(,82)
 table=81, priority=80,ct_state=+trk,reg5=0x2 actions=resubmit(,82)
 table=81, priority=0 actions=drop

Similarly to |table_72|, |table_82| accepts established and related
connections. In this case we allow all ICMP traffic coming from
``security group 1`` which is in this case only ``port 1``.
The first four flows match on the IP addresses, and the
next two flows match on the ICMP protocol.
These six flows define conjunction flows, and the next two define actions for
them.

::

 table=82, priority=71,ct_state=+est-rel-rpl,ip,reg6=0x284,nw_src=192.168.0.1 actions=conjunction(18,1/2)
 table=82, priority=71,ct_state=+est-rel-rpl,ip,reg6=0x284,nw_src=10.0.0.1 actions=conjunction(18,1/2)
 table=82, priority=71,ct_state=+new-est,ip,reg6=0x284,nw_src=192.168.0.1 actions=conjunction(19,1/2)
 table=82, priority=71,ct_state=+new-est,ip,reg6=0x284,nw_src=10.0.0.1 actions=conjunction(19,1/2)
 table=82, priority=71,ct_state=+est-rel-rpl,icmp,reg5=0x2 actions=conjunction(18,2/2)
 table=82, priority=71,ct_state=+new-est,icmp,reg5=0x2 actions=conjunction(19,2/2)
 table=82, priority=71,conj_id=18,ct_state=+est-rel-rpl,ip,reg5=0x2 actions=strip_vlan,output:2
 table=82, priority=71,conj_id=19,ct_state=+new-est,ip,reg5=0x2 actions=ct(commit,zone=NXM_NX_REG6[0..15]),strip_vlan,output:2,resubmit(,92)
 table=82, priority=50,ct_state=+inv+trk actions=resubmit(,93)

There are some more security group rules with remote group IDs. Next
we look at TCP related ones. Excerpt of flows that correspond to those
rules are:

::

 table=82, priority=73,ct_state=+est-rel-rpl,tcp,reg5=0x2,tp_dst=0x60/0xffe0 actions=conjunction(22,2/2)
 table=82, priority=73,ct_state=+new-est,tcp,reg5=0x2,tp_dst=0x60/0xffe0 actions=conjunction(23,2/2)
 table=82, priority=73,ct_state=+est-rel-rpl,tcp,reg5=0x2,tp_dst=0x40/0xfff0 actions=conjunction(22,2/2)
 table=82, priority=73,ct_state=+new-est,tcp,reg5=0x2,tp_dst=0x40/0xfff0 actions=conjunction(23,2/2)
 table=82, priority=73,ct_state=+est-rel-rpl,tcp,reg5=0x2,tp_dst=0x58/0xfff8 actions=conjunction(22,2/2)
 table=82, priority=73,ct_state=+new-est,tcp,reg5=0x2,tp_dst=0x58/0xfff8 actions=conjunction(23,2/2)
 table=82, priority=73,ct_state=+est-rel-rpl,tcp,reg5=0x2,tp_dst=0x54/0xfffc actions=conjunction(22,2/2)
 table=82, priority=73,ct_state=+new-est,tcp,reg5=0x2,tp_dst=0x54/0xfffc actions=conjunction(23,2/2)
 table=82, priority=73,ct_state=+est-rel-rpl,tcp,reg5=0x2,tp_dst=0x52/0xfffe actions=conjunction(22,2/2)
 table=82, priority=73,ct_state=+new-est,tcp,reg5=0x2,tp_dst=0x52/0xfffe actions=conjunction(23,2/2)
 table=82, priority=73,ct_state=+est-rel-rpl,tcp,reg5=0x2,tp_dst=80 actions=conjunction(22,2/2),conjunction(14,2/2)
 table=82, priority=73,ct_state=+est-rel-rpl,tcp,reg5=0x2,tp_dst=81 actions=conjunction(22,2/2)
 table=82, priority=73,ct_state=+new-est,tcp,reg5=0x2,tp_dst=80 actions=conjunction(23,2/2),conjunction(15,2/2)
 table=82, priority=73,ct_state=+new-est,tcp,reg5=0x2,tp_dst=81 actions=conjunction(23,2/2)

Only dimension 2/2 flows are shown here, as the other are similar to
the previous ICMP example. There are many more flows but only the port
ranges that cover from 64 to 127 are shown for brevity.

The conjunction IDs 14 and 15 correspond to packets from the security
group 1, and the conjunction IDs 22 and 23 correspond to those from
the security group 2. These flows are from the following security group rules,

::

      - can receive TCP packets from security group 1
      - can receive TCP packets to port 80 from security group 2

and these rules have been processed by ``merge_port_ranges`` into:

::

      - can receive TCP packets to port != 80 from security group 1
      - can receive TCP packets to port 80 from security group 1 or 2

before translating to flows so that there is only one matching flow
even when the TCP destination port is 80.

The remaining is a L4 protocol agnostic rule.

::

 table=82, priority=70,ct_state=+est-rel-rpl,ip,reg5=0x2 actions=conjunction(24,2/2)
 table=82, priority=70,ct_state=+new-est,ip,reg5=0x2 actions=conjunction(25,2/2)

Any IP packet that matches the previous TCP flows matches one of these
flows, but the corresponding security group rules have different
remote group IDs.  Unlike the above TCP example, there's no convenient
way of expressing ``protocol != TCP`` or ``icmp_code != 1``.  So the
OVS firewall uses a different priority than the previous TCP flows so
as not to mix them up.

The mechanism for dropping connections that are not allowed anymore is the
same as in |table_72|.

::

 table=82, priority=50,ct_mark=0x1,reg5=0x1 actions=resubmit(,93)
 table=82, priority=50,ct_mark=0x1,reg5=0x2 actions=resubmit(,93)
 table=82, priority=50,ct_state=+est-rel+rpl,ct_zone=644,ct_mark=0,reg5=0x1 actions=strip_vlan,output:1
 table=82, priority=50,ct_state=+est-rel+rpl,ct_zone=644,ct_mark=0,reg5=0x2 actions=strip_vlan,output:2
 table=82, priority=50,ct_state=-new-est+rel-inv,ct_zone=644,ct_mark=0,reg5=0x1 actions=strip_vlan,output:1
 table=82, priority=50,ct_state=-new-est+rel-inv,ct_zone=644,ct_mark=0,reg5=0x2 actions=strip_vlan,output:2
 table=82, priority=40,ct_state=-est,reg5=0x1 actions=resubmit(,93)
 table=82, priority=40,ct_state=+est,reg5=0x1 actions=ct(commit,zone=NXM_NX_REG6[0..15],exec(load:0x1->NXM_NX_CT_MARK[]))
 table=82, priority=40,ct_state=-est,reg5=0x2 actions=resubmit(,93)
 table=82, priority=40,ct_state=+est,reg5=0x2 actions=ct(commit,zone=NXM_NX_REG6[0..15],exec(load:0x1->NXM_NX_CT_MARK[]))
 table=82, priority=0 actions=drop


.. note::

  Conntrack zones on a single node are now based on the network to which
  a port is plugged in. That makes a difference between traffic on hypervisor
  only and east-west traffic. For example, if a port has a VIP that was
  migrated to a port on a different node, then the new port won't contain
  conntrack information about previous traffic that happened with that VIP.

By default |table_94| will have one single flow like this:

::

  table=94, priority=1 actions=NORMAL

If ``explicitly_egress_direct`` is set to True, flows of |table_94|
will be:

::

  table=94, priority=12,reg6=0x284,dl_dst=fa:16:3e:a4:22:10 actions=output:1
  table=94, priority=12,reg6=0x284,dl_dst=fa:16:3e:24:57:c7 actions=output:2
  table=94, priority=10,reg6=0x284,dl_src=fa:16:3e:a4:22:10,dl_dst=00:00:00:00:00:00/01:00:00:00:00:00 actions=push_vlan:0x8100,set_field:0x1->vlan_vid,output:3
  table=94, priority=10,reg6=0x284,dl_src=fa:16:3e:24:57:c7,dl_dst=00:00:00:00:00:00/01:00:00:00:00:00 actions=push_vlan:0x8100,set_field:0x1->vlan_vid,output:3
  table=94, priority=1 actions=NORMAL

The OVS firewall will initialize a default goto table 94 flow
on TRANSIENT_TABLE |table_60|, if ``explicitly_egress_direct``
is set to True, which is mainly for ports without security groups
and disabled port_security. For instance:

::
  table=60, priority=2 actions=resubmit(,94)

Then for packets from the outside to VM without security functionalities
(--disable-port-security --no-security-group)
will go to table 94 and do the same direct actions.


OVS firewall integration points
-------------------------------

There are three tables where packets are sent once after going through the OVS
firewall pipeline. The tables can be used by other mechanisms that are supposed
to work with the OVS firewall, typically L2 agent extensions.

Egress pipeline
~~~~~~~~~~~~~~~

Packets are sent to |table_91| and |table_94| when they are considered accepted
by the egress pipeline, and they will be processed so that they are forwarded
to their destination by being submitted to a NORMAL action, that results in
Ethernet flood/learn processing.

Two tables are used to differentiate between the first packets of a connection
and the following packets. This was introduced for performance reasons to
allow the logging extension to only log the first packets of a connection.
Only the first accepted packet of each connection session will go to |table_91|
and the following ones will go to |table_94|.

Note that |table_91| merely resubmits to |table_94| that contains the actual
NORMAL action; this allows to have a single place where the NORMAL action can
be overridden by other components (currently used by ``networking-bagpipe``
driver for ``networking-bgpvpn``).

Ingress pipeline
~~~~~~~~~~~~~~~~

The first packet of each connection accepted by the ingress pipeline is sent
to |table_92|. The default action in this table is DROP because at this point
the packets have already been delivered to their destination port. This
integration point is essentially provided for the logging extension.

Packets are sent to |table_93| if processing by the ingress filtering
concluded that they should be dropped.

Upgrade path from iptables hybrid driver
----------------------------------------

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

4) Once migration is complete, stale iptables rules should be cleaned-up on
all nodes where the firewall driver was changed. They can be found by
searching for the string 'neutron', for example:

.. code-block:: bash

    sudo iptables -S | grep neutron

.. note::

  During upgrading to openvswitch firewall, the security rules
  are still working for previous iptables controlled hybrid ports. But it will
  not work if one tries to replace openvswitch firewall with iptables.

.. |table_0| replace:: ``table 0`` (LOCAL_SWITCHING)
.. |table_59| replace:: ``table 59`` (PACKET_RATE_LIMIT)
.. |table_60| replace:: ``table 60`` (TRANSIENT)
.. |table_71| replace:: ``table 71`` (BASE_EGRESS)
.. |table_72| replace:: ``table 72`` (RULES_EGRESS)
.. |table_73| replace:: ``table 73`` (ACCEPT_OR_INGRESS)
.. |table_81| replace:: ``table 81`` (BASE_INGRESS)
.. |table_82| replace:: ``table 82`` (RULES_INGRESS)
.. |table_91| replace:: ``table 91`` (ACCEPTED_EGRESS_TRAFFIC)
.. |table_92| replace:: ``table 92`` (ACCEPTED_INGRESS_TRAFFIC)
.. |table_93| replace:: ``table 93`` (DROPPED_TRAFFIC)
.. |table_94| replace:: ``table 94`` (ACCEPTED_EGRESS_TRAFFIC_NORMAL)
