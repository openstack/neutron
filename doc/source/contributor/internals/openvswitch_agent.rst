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


Open vSwitch L2 Agent
=====================

This Agent uses the `Open vSwitch`_ virtual switch to create L2
connectivity for instances, along with bridges created in conjunction
with OpenStack Nova for filtering.

ovs-neutron-agent can be configured to use different networking technologies
to create project isolation.
These technologies are implemented as ML2 type drivers which are used in
conjunction with the Open vSwitch mechanism driver.

VLAN Tags
---------

.. image:: images/under-the-hood-scenario-1-ovs-compute.png

.. _Open vSwitch: http://openvswitch.org


GRE Tunnels
-----------

GRE Tunneling is documented in depth in the `Networking in too much detail
<http://openstack.redhat.com/networking/networking-in-too-much-detail/>`_
by RedHat.

VXLAN Tunnels
-------------

VXLAN is an overlay technology which encapsulates MAC frames
at layer 2 into a UDP header.
More information can be found in `The VXLAN wiki page.
<http://en.wikipedia.org/wiki/Virtual_Extensible_LAN>`_

Geneve Tunnels
--------------

Geneve uses UDP as its transport protocol and is dynamic
in size using extensible option headers.
It is important to note that currently it is only supported in
newer kernels. (kernel >= 3.18, OVS version >=2.4)
More information can be found in the `Geneve RFC document.
<https://tools.ietf.org/html/draft-ietf-nvo3-geneve-00>`_


Bridge Management
-----------------

In order to make the agent capable of handling more than one tunneling
technology, to decouple the requirements of segmentation technology
from project isolation, and to preserve backward compatibility for OVS
agents working without tunneling, the agent relies on a tunneling bridge,
or br-tun, and the well known integration bridge, or br-int.

All VM VIFs are plugged into the integration bridge. VM VIFs on a given
virtual network share a common "local" VLAN (i.e. not propagated
externally). The VLAN id of this local VLAN is mapped to the physical
networking details realizing that virtual network.

For virtual networks realized as VXLAN/GRE tunnels, a Logical Switch
(LS) identifier is used to differentiate project traffic on inter-HV
tunnels. A mesh of tunnels is created to other Hypervisors in the
cloud. These tunnels originate and terminate on the tunneling bridge
of each hypervisor, leaving br-int unaffected. Port patching is done
to connect local VLANs on the integration bridge to inter-hypervisor
tunnels on the tunnel bridge.

For each virtual network realized as a VLAN or flat network, a veth
or a pair of patch ports is used to connect the local VLAN on
the integration bridge with the physical network bridge, with flow
rules adding, modifying, or stripping VLAN tags as necessary, thus
preserving backward compatibility with the way the OVS agent used
to work prior to the tunneling capability (for more details, please
look at https://review.opendev.org/#/c/4367).

Bear in mind, that this design decision may be overhauled in the
future to support existing VLAN-tagged traffic (coming from NFV VMs
for instance) and/or to deal with potential QinQ support natively
available in the Open vSwitch.

OVS Filtering Tables
--------------------

ovs-neutron-agent and other L2 agent extensions use OVS filtering tables.

For the list of tables and the short name for them used in Neutron see
`ovs-neutron-agent constants`_

For a detailed discussion of Open vSwitch firewall driver and how the
filtering tables are used for security-groups see :doc:`openvswitch_firewall`.

.. _ovs-neutron-agent constants: https://opendev.org/openstack/neutron-lib/src/branch/master/neutron_lib/constants.py

Tackling the Network Trunking use case
--------------------------------------

Rationale
~~~~~~~~~

At the time the first design for the OVS agent came up, trunking
in OpenStack was merely a pipe dream. Since then, lots has happened
in the OpenStack platform, and many deployments have gone into
production since early 2012.

In order to address the `vlan-aware-vms <http://specs.openstack.org/openstack/neutron-specs/specs/newton/vlan-aware-vms.html>`_
use case on top of Open vSwitch, the following aspects must be
taken into account:

* Design complexity: starting afresh is always an option, but a
  complete rearchitecture is only desirable under some
  circumstances. After all, customers want solutions...yesterday.
  It is noteworthy that the OVS agent design is already relatively
  complex, as it accommodates a number of deployment options,
  especially in relation to security rules and/or acceleration.
* Upgrade complexity: being able to retrofit the existing
  design means that an existing deployment does not need to go
  through a forklift upgrade in order to expose new functionality;
  alternatively, the desire of avoiding a migration requires a
  more complex solution that is able to support multiple modes of
  operations;
* Design reusability: ideally, a proposed design can easily apply
  to the various technology backends that the Neutron L2 agent
  supports: Open vSwitch and Linux Bridge.
* Performance penalty: no solution is appealing enough if
  it is unable to satisfy the stringent requirement of high
  packet throughput, at least in the long term.
* Feature compatibility: VLAN `transparency <http://specs.openstack.org/openstack/neutron-specs/specs/kilo/nfv-vlan-trunks.html>`_
  is for better or for worse intertwined with vlan awareness.
  The former is about making the platform not interfere with the
  tag associated to the packets sent by the VM, and let the
  underlay figure out where the packet needs to be sent out; the
  latter is about making the platform use the vlan tag associated
  to packet to determine where the packet needs to go. Ideally,
  a design choice to satisfy the awareness use case will not have
  a negative impact for solving the transparency use case. Having
  said that, the two features are still meant to be mutually
  exclusive in their application, and plugging subports into
  networks whose vlan-transparency flag is set to True might have
  unexpected results.  In fact, it would be impossible from the
  platform's point of view discerning which tagged packets are meant
  to be treated 'transparently' and which ones are meant to be used
  for demultiplexing (in order to reach the right destination).
  The outcome might only be predictable if two layers of vlan tags
  are stacked up together, making guest support even more crucial
  for the combined use case.

It is clear by now that an acceptable solution must be assessed
with these issues in mind. The potential solutions worth enumerating
are:

* VLAN interfaces: in layman's terms, these interfaces allow to
  demux the traffic before it hits the integration bridge where
  the traffic will get isolated and sent off to the right
  destination. This solution is `proven <https://etherpad.openstack.org/p/vlan@tap_experiment>`_
  to work for both iptables-based and native ovs security rules
  (credit to Rawlin Peters). This solution has the following design
  implications:

  * Design complexity: this requires relative small changes
    to the existing OVS design, and it can work with both
    iptables and native ovs security rules.
  * Upgrade complexity: in order to employ this solution
    no major upgrade is necessary and thus no potential dataplane
    disruption is involved.
  * Design reusability: VLAN interfaces can easily be employed
    for both Open vSwitch and Linux Bridge.
  * Performance penalty: using VLAN interfaces means that the
    kernel must be involved. For Open vSwitch, being able to use
    a fast path like DPDK would be an unresolved issue (`Kernel NIC interfaces <http://dpdk.org/doc/guides/prog_guide/kernel_nic_interface.html>`_
    are not on the roadmap for distros and OVS, and most likely
    will never be). Even in the absence of an extra bridge, i.e. when
    using native ovs firewall, and with the advent of userspace
    connection tracking that would allow the `stateful firewall driver <https://bugs.launchpad.net/neutron/+bug/1461000>`_
    to work with DPDK, the performance gap between a pure
    userspace DPDK capable solution and a kernel based solution
    will be substantial, at least under certain traffic conditions.
  * Feature compatibility: in order to keep the design simple once
    VLAN interfaces are adopted, and yet enable VLAN transparency,
    Open vSwitch needs to support QinQ, which is currently lacking
    as of 2.5 and with no ongoing plan for integration.

* Going full openflow: in layman's terms, this means programming the
  dataplane using OpenFlow in order to provide tenant isolation, and
  packet processing. This solution has the following design implications:

  * Design complexity: this requires a big rearchitecture of the
    current Neutron L2 agent solution.
  * Upgrade complexity: existing deployments will be unable to
    work correctly unless one of the actions take place: a) the
    agent can handle both the 'old' and 'new' way of wiring the
    data path; b) a dataplane migration is forced during a release
    upgrade and thus it may cause (potentially unrecoverable) dataplane
    disruption.
  * Design reusability: a solution for Linux Bridge will still
    be required to avoid widening the gap between Open vSwitch
    (e.g. OVS has DVR but LB does not).
  * Performance penalty: using Open Flow will allow to leverage
    the user space and fast processing given by DPDK, but at
    a considerable engineering cost nonetheless. Security rules
    will have to be provided by a `learn based firewall <https://github.com/openstack/networking-ovs-dpdk>`_
    to fully exploit the capabilities of DPDK, at least until
    `user space <https://patchwork.ozlabs.org/patch/611282/>`_
    connection tracking becomes available in OVS.
  * Feature compatibility: with the adoption of Open Flow, tenant
    isolation will no longer be provided by means of local vlan
    provisioning, thus making the requirement of QinQ support
    no longer strictly necessary for Open vSwitch.

* Per trunk port OVS bridge: in layman's terms, this is similar to
  the first option, in that an extra layer of mux/demux is introduced
  between the VM and the integration bridge (br-int) but instead of
  using vlan interfaces, a combination of a new per port OVS bridge
  and patch ports to wire this new bridge with br-int will be used.
  This solution has the following design implications:

  * Design complexity: the complexity of this solution can be
    considered in between the above mentioned options in that
    some work is already available since `Mitaka <https://blueprints.launchpad.net/nova/+spec/neutron-ovs-bridge-name>`_
    and the data path wiring logic can be partially reused.
  * Upgrade complexity: if two separate code paths are assumed
    to be maintained in the OVS agent to handle regular ports
    and ports participating a trunk with no ability to convert
    from one to the other (and vice versa), no migration is
    required. This is done at a cost of some loss of flexibility
    and maintenance complexity.
  * Design reusability: a solution to support vlan trunking for
    the Linux Bridge mech driver will still be required to avoid
    widening the gap with Open vSwitch (e.g. OVS has DVR but
    LB does not).
  * Performance penalty: from a performance standpoint, the adoption
    of a trunk bridge relieves the agent from employing kernel
    interfaces, thus unlocking the full potential of fast packet
    processing. That said, this is only doable in combination with
    a native ovs firewall. At the time of writing the only DPDK
    enabled firewall driver is the learn based one available in
    the `networking-ovs-dpdk repo <https://github.com/openstack/networking-ovs-dpdk>`_;
  * Feature compatibility: the existing local provisioning logic
    will not be affected by the introduction of a trunk bridge,
    therefore use cases where VMs are connected to a vlan transparent
    network via a regular port will still require QinQ support
    from OVS.

To summarize:

* VLAN interfaces (A) are compelling because will lead to a relatively
  contained engineering cost at the expense of performance. The Open
  vSwitch community will need to be involved in order to deliver vlan
  transparency. Irrespective of whether this strategy is chosen for
  Open vSwitch or not, this is still the only viable approach for Linux
  Bridge and thus pursued to address Linux Bridge support for VLAN
  trunking. To some extent, this option can also be considered a fallback
  strategy for OVS deployments that are unable to adopt DPDK.

* Open Flow (B) is compelling because it will allow Neutron to unlock
  the full potential of Open vSwitch, at the expense of development
  and operations effort. The development is confined within the
  boundaries of the Neutron community in order to address vlan awareness
  and transparency (as two distinct use cases, ie. to be adopted
  separately).
  Stateful firewall (based on ovs conntrack) limits the adoption for
  DPDK at the time of writing, but a learn-based firewall can be a
  suitable alternative. Obviously this solution is not compliant with
  iptables firewall.

* Trunk Bridges (C) tries to bring the best of option A and B together
  as far as OVS development and performance are concerned, but it
  comes at the expense of maintenance complexity and loss of flexibility.
  A Linux Bridge solution would still be required and, QinQ support will
  still be needed to address vlan transparency.

All things considered, as far as OVS is concerned, option (C) is the most
promising in the medium term. Management of trunks and ports within trunks
will have to be managed differently and, to start with, it is sensible to
restrict the ability to update ports (i.e. convert) once they are bound to
a particular bridge (integration vs trunk). Security rules via iptables
rules is obviously not supported, and never will be.

Option (A) for OVS could be pursued in conjunction with Linux Bridge support,
if the effort is seen particularly low hanging fruit.
However, a working solution based on this option positions the OVS agent as
a sub-optminal platform for performance sensitive applications in comparison
to other accelerated or SDN-controller based solutions. Since further data
plane performance improvement is hindered by the extra use of kernel resources,
this option is not at all appealing in the long term.

Embracing option (B) in the long run may be complicated by the adoption of
option (C). The development and maintenance complexity involved in Option
(C) and (B) respectively poses the existential question as to whether
investing in the agent-based architecture is an effective strategy,
especially if the end result would look a lot like other maturing
alternatives.

Implementation VLAN Interfaces (Option A)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This implementation doesn't require any modification of the vif-drivers since
Nova will plug the vif of the VM the same way as it does for traditional ports.

Trunk port creation
+++++++++++++++++++
A VM is spawned passing to Nova the port-id of a parent port associated with
a trunk. Nova/libvirt will create the tap interface and will plug it into
br-int or into the firewall bridge if using iptables firewall. In the
external-ids of the port Nova will store the port ID of the parent port.
The OVS agent detects that a new vif has been plugged. It gets
the details of the new port and wires it.
The agent configures it in the same way as a traditional port: packets coming
out from the VM will be tagged using the internal VLAN ID associated to the
network, packets going to the VM will be stripped of the VLAN ID.
After wiring it successfully the OVS agent will send a message notifying
Neutron server that the parent port is up. Neutron will send back to Nova an
event to signal that the wiring was successful.
If the parent port is associated with one or more subports the agent will
process them as described in the next paragraph.

Subport creation
++++++++++++++++
If a subport is added to a parent port but no VM was booted using that parent
port yet, no L2 agent will process it (because at that point the parent port is
not bound to any host).
When a subport is created for a parent port and a VM that uses that parent port
is already running, the OVS agent will create a VLAN interface on the VM tap
using the VLAN ID specified in the subport segmentation id. There's a small
possibility that a race might occur: the firewall bridge might be created and
plugged while the vif is not there yet. The OVS agent needs to check if the
vif exists before trying to create a subinterface.
Let's see how the models differ when using the iptables firewall or the OVS
native firewall.

Iptables Firewall
'''''''''''''''''

::

         +----------------------------+
         |             VM             |
         |   eth0            eth0.100 |
         +-----+-----------------+----+
               |
               |
           +---+---+       +-----+-----+
           | tap1  |-------|  tap1.100 |
           +---+---+       +-----+-----+
               |                 |
               |                 |
           +---+---+         +---+---+
           | qbr1  |         | qbr2  |
           +---+---+         +---+---+
               |                 |
               |                 |
         +-----+-----------------+----+
         |    port 1          port 2  |
         |   (tag 3)         (tag 5)  |
         |           br-int           |
         +----------------------------+

Let's assume the subport is on network2 and uses segmentation ID 100.
In the case of hybrid plugging the OVS agent will have to create the firewall
bridge (qbr2), create tap1.100 and plug it into qbr2. It will connect qbr2 to
br-int and set the subport ID in the external-ids of port 2.

*Inbound traffic from the VM point of view*

The untagged traffic will flow from port 1 to eth0 through qbr1.
For the traffic coming out of port 2, the internal VLAN ID of network2 will be
stripped. The packet will then go untagged through qbr2 where
iptables rules will filter the traffic. The tag 100 will be pushed by tap1.100
and the packet will finally get to eth0.100.

*Outbound traffic from the VM point of view*

The untagged traffic will flow from eth0 to port1 going through qbr1 where
firewall rules will be applied. Traffic tagged with VLAN 100 will leave
eth0.100, go through tap1.100 where the VLAN 100 is stripped. It will reach
qbr2 where iptables rules will be applied and go to port 2. The internal VLAN
of network2 will be pushed by br-int when the packet enters port2 because it's
a tagged port.


OVS Firewall case
'''''''''''''''''

::

         +----------------------------+
         |             VM             |
         |   eth0            eth0.100 |
         +-----+-----------------+----+
               |
               |
           +---+---+       +-----+-----+
           | tap1  |-------|  tap1.100 |
           +---+---+       +-----+-----+
               |                 |
               |                 |
               |                 |
         +-----+-----------------+----+
         |    port 1          port 2  |
         |   (tag 3)         (tag 5)  |
         |           br-int           |
         +----------------------------+

When a subport is created the OVS agent will create the VLAN interface tap1.100
and plug it into br-int. Let's assume the subport is on network2.

*Inbound traffic from the VM point of view*

The traffic will flow untagged from port 1 to eth0. The traffic going out from
port 2 will be stripped of the VLAN ID assigned to network2. It will be
filtered by the rules installed by the firewall and reach tap1.100.
tap1.100 will tag the traffic using VLAN 100. It will then reach the VM's
eth0.100.

*Outbound traffic from the VM point of view*

The untagged traffic will flow and reach port 1 where it will be tagged using
the VLAN ID associated to the network. Traffic tagged with VLAN 100 will leave
eth0.100 and reach tap1.100 where VLAN 100 will be stripped. It will then reach
port2. It will be filtered by the rules installed by the firewall on port 2.
Then the packets will be tagged using the internal VLAN associated to network2
by br-int since port 2 is a tagged port.

Parent port deletion
++++++++++++++++++++

Deleting a port that is an active parent in a trunk is forbidden. If the parent
port has no trunk associated (it's a "normal" port), it can be deleted.
The OVS agent doesn't need to perform any action, the deletion will result in
a removal of the port data from the DB.


Trunk deletion
++++++++++++++

When Nova deletes a VM, it deletes the VM's corresponding Neutron ports only if
they were created by Nova when booting the VM. In the vlan-aware-vm case the
parent port is passed to Nova, so the port data will remain in the DB after the
VM deletion. Nova will delete the VIF of the VM (in the example tap1) as part
of the VM termination. The OVS agent will detect that deletion and notify the
Neutron server that the parent port is down. The OVS agent will clean up the
corresponding subports as explained in the next paragraph.

The deletion of a trunk that is used by a VM is not allowed.
The trunk can be deleted (leaving the parent port intact) when the parent port
is not used by any VM. After the trunk is deleted, the parent port can also be
deleted.

Subport deletion
++++++++++++++++

Removing a subport that is associated with a parent port that was not used to
boot any VM is a no op from the OVS agent perspective.
When a subport associated with a parent port that was used to boot a VM is
deleted, the OVS agent will take care of removing the firewall bridge if using
the iptables firewall, and the port on br-int.


Implementation Trunk Bridge (Option C)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This implementation is based on this `etherpad <https://etherpad.openstack.org/p/trunk-bridge-tagged-patch-experiment>`_.
Credits to Bence Romsics.
The IDs used for bridge and port names are truncated.

::

         +--------------------------------+
         |             VM                 |
         |   eth0               eth0.100  |
         +-----+--------------------+-----+
               |
               |
         +-----+--------------------------+
         |    tap1                        |
         |          tbr-trunk-id          |
         |                                |
         | tpt-parent-id   spt-subport-id |
         |  (tag 0)          (tag 100)    |
         +-----+-----------------+--------+
               |                 |
               |                 |
               |                 |
         +-----+-----------------+---------+
         | tpi-parent-id    spi-subport-id |
         |  (tag 3)           (tag 5)      |
         |                                 |
         |           br-int                |
         +---------------------------------+

tpt-parent-id: trunk bridge side of the patch port that implements a trunk.
tpi-parent-id: int bridge side of the patch port that implements a trunk.
spt-subport-id: trunk bridge side of the patch port that implements a subport.
spi-subport-id: int bridge side of the patch port that implements a subport.

Trunk creation
++++++++++++++

A VM is spawned passing to Nova the port-id of a parent port associated
with a trunk. Neutron will pass to Nova the bridge where to plug the
vif as part of the vif details.  The os-vif driver creates the trunk
bridge tbr-trunk-id if it does not exist in plug().  It will create the
tap interface tap1 and plug it into tbr-trunk-id setting the parent port
ID in the external-ids.  The trunk driver will wire the parent port via
a patch port to connect the trunk bridge to the integration bridge:

::

 ovs-vsctl add-port tbr-trunk-id tpt-parent-id -- set Interface tpt-parent-id type=patch options:peer=tpi-parent-id -- set Port tpt-parent-id vlan_mode=access tag=0
 ovs-vsctl add-port br-int tpi-parent-id -- set Interface tpi-parent-id type=patch options:peer=tpt-parent-id


tpt-parent-id, the trunk bridge side of the patch will carry untagged
traffic (vlan_mode=access tag=0).  The OVS agent will be monitoring the
creation of ports on the integration bridge.  tpi-parent-id, the br-int
side the patch port is tagged with VLAN 3 by ovs-agent.  We assume that
the trunk is on network1 that on this host is associated with VLAN 3.
If the parent port is associated with one or more subports the agent
will process them as described in the next paragraph.

Subport creation
++++++++++++++++

If a subport is added to a parent port but no VM was booted using that parent
port yet, the agent won't process the subport (because at this point there's
no node associated with the parent port).
When a subport is added to a parent port that is used by a VM the OVS agent
will create a new patch port:

::

 ovs-vsctl add-port tbr-trunk-id spt-subport-id tag=100 -- set Interface spt-subport-id type=patch options:peer=spi-subport-id
 ovs-vsctl add-port br-int spi-subport-id tag=5 -- set Interface spi-subport-id type=patch options:peer=spt-subport-id

This patch port connects the trunk bridge to the integration bridge.
spt-subport-id, the trunk bridge side of the patch is tagged using VLAN 100.
We assume that the segmentation ID of the subport is 100.
spi-subport-id, the br-int side of the patch port is tagged with VLAN 5. We
assume that the subport is on network2 that on this host uses VLAN 5.
The OVS agent will set the subport ID in the external-ids of spt-subport-id
and spi-subport-id.

*Inbound traffic from the VM point of view*

The traffic coming out of tpi-parent-id will be stripped by br-int of VLAN 3.
It will reach tpt-parent-id untagged and from there tap1.
The traffic coming out of spi-subport-id will be stripped by br-int of VLAN 5.
It will reach spt-subport-id where it will be tagged with VLAN 100 and it will
then get to tap1 tagged.


*Outbound traffic from the VM point of view*

The untagged traffic coming from tap1 will reach tpt-parent-id and from there
tpi-parent-id where it will be tagged using VLAN 3.
The traffic tagged with VLAN 100 from tap1 will reach spt-subport-id.
VLAN 100 will be stripped since spt-subport-id is a tagged port and the packet
will reach spi-subport-id, where it's tagged using VLAN 5.

Parent port deletion
++++++++++++++++++++

Deleting a port that is an active parent in a trunk is forbidden. If the parent
port has no trunk associated, it can be deleted. The OVS agent doesn't need to
perform any action.

Trunk deletion
++++++++++++++

When Nova deletes a VM, it deletes the VM's corresponding Neutron ports only if
they were created by Nova when booting the VM. In the vlan-aware-vm case the
parent port is passed to Nova, so the port data will remain in the DB after the
VM deletion. Nova will delete the port on the trunk bridge where the VM is
plugged. The L2 agent will detect that and delete the trunk bridge. It will
notify the Neutron server that the parent port is down.

The deletion of a trunk that is used by a VM is not allowed.
The trunk can be deleted (leaving the parent port intact) when the parent port
is not used by any VM. After the trunk is deleted, the parent port can also be
deleted.

Subport deletion
++++++++++++++++

The OVS agent will delete the patch port pair corresponding to the subport
deleted.

Agent resync
~~~~~~~~~~~~

During resync the agent should check that all the trunk and subports are
still valid. It will delete the stale trunk and subports using the procedure
specified in the previous paragraphs according to the implementation.


Local IP
--------

Local IP is a new feature added in Yoga release. For details on openvswitch
agent impact please see:
:doc:`Local IPs <local_ips>`.


Further Reading
---------------

* `Darragh O'Reilly - The Open vSwitch plugin with VLANs <http://techbackground.blogspot.com/2013/07/the-open-vswitch-plugin-with-vlans.html>`_
