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

TODO: Rules below will be awesomly explained

::

 table=0, priority=100,in_port=2 actions=load:0x2->NXM_NX_REG5[],resubmit(,71)
 table=0, priority=100,in_port=1 actions=load:0x1->NXM_NX_REG5[],resubmit(,71)
 table=0, priority=90,dl_dst=fa:16:3e:9b:67:b2 actions=load:0x2->NXM_NX_REG5[],resubmit(,81)
 table=0, priority=90,dl_dst=fa:16:3e:44:de:7a actions=load:0x1->NXM_NX_REG5[],resubmit(,81)
 table=0, priority=0 actions=NORMAL
 table=0, priority=1 actions=NORMAL
 table=71, priority=95,arp,in_port=2,dl_src=fa:16:3e:9b:67:b2,arp_spa=192.168.0.2 actions=NORMAL
 table=71, priority=95,arp,in_port=1,dl_src=fa:16:3e:44:de:7a,arp_spa=192.168.0.1 actions=NORMAL
 table=71, priority=90,ct_state=-trk,in_port=2,dl_src=fa:16:3e:9b:67:b2 actions=ct(table=72,zone=NXM_NX_REG5[0..15])
 table=71, priority=90,ct_state=-trk,in_port=1,dl_src=fa:16:3e:44:de:7a actions=ct(table=72,zone=NXM_NX_REG5[0..15])
 table=71, priority=70,udp,in_port=2,tp_src=68,tp_dst=67 actions=NORMAL
 table=71, priority=70,udp6,in_port=2,tp_src=546,tp_dst=547 actions=NORMAL
 table=71, priority=60,udp,in_port=2,tp_src=67,tp_dst=68 actions=drop
 table=71, priority=60,udp6,in_port=2,tp_src=547,tp_dst=546 actions=drop
 table=71, priority=70,udp,in_port=1,tp_src=68,tp_dst=67 actions=NORMAL
 table=71, priority=70,udp6,in_port=1,tp_src=546,tp_dst=547 actions=NORMAL
 table=71, priority=60,udp,in_port=1,tp_src=67,tp_dst=68 actions=drop
 table=71, priority=60,udp6,in_port=1,tp_src=547,tp_dst=546 actions=drop
 table=71, priority=10,ct_state=-trk,in_port=2 actions=drop
 table=71, priority=10,ct_state=-trk,in_port=1 actions=drop
 table=71, priority=0 actions=drop
 table=72, priority=90,ct_state=+inv+trk actions=drop
 table=72, priority=80,ct_state=+est-rel-inv+trk actions=NORMAL
 table=72, priority=80,ct_state=-est+rel-inv+trk actions=NORMAL
 table=72, priority=70,icmp,dl_src=fa:16:3e:44:de:7a,nw_src=192.168.0.1 actions=resubmit(,73)
 table=72, priority=0 actions=drop
 table=73, priority=100,dl_dst=fa:16:3e:9b:67:b2 actions=resubmit(,81)
 table=73, priority=100,dl_dst=fa:16:3e:44:de:7a actions=resubmit(,81)
 table=73, priority=90,in_port=2 actions=ct(commit,zone=NXM_NX_REG5[0..15])
 table=73, priority=90,in_port=1 actions=ct(commit,zone=NXM_NX_REG5[0..15])
 table=81, priority=100,arp,dl_dst=fa:16:3e:9b:67:b2 actions=output:2
 table=81, priority=100,arp,dl_dst=fa:16:3e:44:de:7a actions=output:1
 table=81, priority=95,ct_state=-trk,ip actions=ct(table=82,zone=NXM_NX_REG5[0..15])
 table=81, priority=95,ct_state=-trk,ipv6 actions=ct(table=82,zone=NXM_NX_REG5[0..15])
 table=81, priority=80,dl_dst=fa:16:3e:9b:67:b2 actions=resubmit(,82)
 table=81, priority=80,dl_dst=fa:16:3e:44:de:7a actions=resubmit(,82)
 table=81, priority=0 actions=drop
 table=82, priority=100,ct_state=+inv+trk actions=drop
 table=82, priority=80,ct_state=+est-rel-inv+trk,dl_dst=fa:16:3e:44:de:7a actions=output:1
 table=82, priority=80,ct_state=-est+rel-inv+trk,dl_dst=fa:16:3e:44:de:7a actions=output:1
 table=82, priority=80,ct_state=+est-rel-inv+trk,dl_dst=fa:16:3e:9b:67:b2 actions=output:2
 table=82, priority=80,ct_state=-est+rel-inv+trk,dl_dst=fa:16:3e:9b:67:b2 actions=output:2
 table=82, priority=70,icmp,dl_dst=fa:16:3e:9b:67:b2,nw_src=192.168.0.1,nw_dst=192.168.0.2 actions=ct(commit,zone=NXM_NX_REG5[0..15]),output:2
 table=82, priority=0 actions=drop


Future work
-----------

 - Conjunctions in Openflow rules can be created to decrease the number of
   rules needed for remote security groups
 - Masking the port range can be used to avoid generating a single rule per
   port number being filtered. For example, if the port range is 1 to 5, one
   rule can be generated instead of 5.
   e.g. tcp,tcp_src=0x03e8/0xfff8
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
