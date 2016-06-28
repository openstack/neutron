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


OpenVSwitch L2 Agent
====================

This Agent uses the `OpenVSwitch`_ virtual switch to create L2
connectivity for instances, along with bridges created in conjunction
with OpenStack Nova for filtering.

ovs-neutron-agent can be configured to use different networking technologies
to create project isolation.
These technologies are implemented as ML2 type drivers which are used in
conjunction with the OpenVSwitch mechanism driver.

VLAN Tags
---------

.. image:: images/under-the-hood-scenario-1-ovs-compute.png

.. _OpenVSwitch: http://openvswitch.org


GRE Tunnels
-----------

GRE Tunneling is documented in depth in the `Networking in too much
detail <http://openstack.redhat.com/Networking_in_too_much_detail>`_
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
look at https://review.openstack.org/#/c/4367).

Bear in mind, that this design decision may be overhauled in the
future to support existing VLAN-tagged traffic (coming from NFV VMs
for instance) and/or to deal with potential QinQ support natively
available in the Open vSwitch.

Tackling the Network Trunking use case
--------------------------------------

Rationale
~~~~~~~~~

At the time the first design for the OVS agent came up, trunking
in OpenStack was merely a pipe dream. Since then, lots has happened
in the OpenStack platform, and many many deployments have gone into
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

Further Reading
---------------

* `Darragh O'Reilly - The Open vSwitch plugin with VLANs <http://techbackground.blogspot.com/2013/07/the-open-vswitch-plugin-with-vlans.html>`_
