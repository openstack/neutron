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


Neutron Stadium
===============

Introduction
------------

Neutron has grown to be a complex project made of many moving parts. The
codebase is the aggregation of smaller projects that, once assembled in a
specific configuration, implement one of the many deployment architectures
to deliver networking services.

This document explains the inclusion process, and the criteria chosen to
select a project for inclusion. It also outlines the lists of projects
that are either managed by the `Neutron teams <http://docs.openstack.org/developer/neutron/policies/neutron-teams.html#neutron-teams>`_,
or that are affiliated to Neutron via an integration point made available
by the core pluggable framework.

Demystifying the mission
------------------------

The Neutron `mission <http://governance.openstack.org/reference/projects/neutron.html#mission>`_
states that Neutron is all about delivering network services and libraries.
Although this has been true for the existence of the project, the project
itself has evolved over the years to meet the demands of a growing community
of users and developers who have an interest in adopting, building new and
leveraging existing network functionality. To continue to stay true to
its mission, and yet reduce the management burden, the project transformed
itself into a pluggable framework, and a community where interested parties
come together to discuss and define APIs and respective implementations that
ultimately are delivered on top of the aforementioned pluggable framework.
Some of these APIs and implementations are considered to be a part of the
Neutron project. For the ones that are not, there is no connotation of
_poor_ quality associated with them. Their association, or lack thereof, is
simply a reflection of the fact that a good portion of Neutron team feels
favorable towards developing, and supporting the project in the wider
OpenStack ecosystem.

Inclusion Process
-----------------

The process for proposing a repo into openstack/ and under the Neutron
project is to propose a patch to the openstack/governance repository.
For example, to propose networking-foo, one would add the following entry
under Neutron in reference/projects.yaml::

    - repo: openstack/networking-foo
      tags:
        - name: release:independent

For more information about the release:independent tag (and other
currently defined tags) see:

    http://governance.openstack.org/reference/tags/

The Neutron PTL must approve the change.  The TC clarified that once a
project has been approved (Neutron in this case), the project can add
additional repos without needing TC approval as long as the added
repositories are within the existing approved scope of the project.

    http://git.openstack.org/cgit/openstack/governance/commit/?id=321a020cbcaada01976478ea9f677ebb4df7bd6d

In order to create a project, in case it does not exist, follow steps
as explained in:

    http://docs.openstack.org/infra/manual/creators.html

Responsibilities
----------------

All affected repositories already have their own review teams.  The
sub-team working on the sub-project is entirely responsible for
day-to-day development.  That includes reviews, bug tracking, and
working on testing.

By being included, the project accepts oversight by the TC as a part of
being in OpenStack, and also accepts oversight by the Neutron PTL.

It is also assumed the respective review teams will make sure their projects
stay in line with `current best practices <sub_project_guidelines.html>`_.

Inclusion Criteria
------------------

As mentioned before, the Neutron PTL must approve the inclusion of each
additional repository under the Neutron project. When in doubt, the PTL
should consider erring on the side of caution, and keep the project out of
the list until more consensus amongst the team can be built or a more
favorable assessment can be determined.
That evaluation will be initially based on the new project requirements used
for all new OpenStack projects for the criteria that is applicable.  If
there is any question about this, the review should be deferred to the TC
as a new OpenStack project team.

    http://governance.openstack.org/reference/new-projects-requirements.html

Including *everything* related to Neutron under the Neutron project team has not
scaled well, so some Neutron related projects are encouraged to form a new
OpenStack project team.  The following list of guidelines are not hard rules.
There may be exceptions.  Instead, they serve as criteria that may influence the
decision one way or the other. Sub-projects will be reviewed regularly to see
how they meet these criteria.

These criteria are designed around how easy it would be for members of the
loosely defined "Neutron team" to jump in and help fix or even take over a given
repository if needed.

* Neutron stays quite busy developing and maintaining open source
  implementations for features.  Any sub-project that serves as an interface to
  proprietary technology should most likely be a separate project team.  This
  imposes a barrier on access to the technology for dev/test and CI integration.
* If the project only interacts with Neutron on REST API boundaries (client of
  Neutron's API, or Neutron is a client of its API), it should probably be a
  separate project.  python-neutronclient is an obvious exception here.
* The area of functionality of a sub-project should be taken into consideration.
  The closer the functionality is to the base functionality implemented in
  openstack/neutron, the more likely it makes sense under the Neutron project
  team.  Conversely, something "higher" in the stack considered an optional
  advanced service is more likely to make sense as an independent project.
  This is subject to change as the Neutron project evolves and continues to
  explore the boundaries that work best for the project.
* OpenStack project teams are based around both technology and groups of people.
  If a sub-project is directly driven by a subset of members of the Neutron team,
  with the wider approval of the Neutron team, then it makes sense to retain it
  under the Neutron project team.  Conversely, a project that was developed
  without oversight or engagement of any of the Neutron members cannot qualify.
  For the sake of this criterion, a member of the team is a known (core or not)
  contributor with a substantial track record of Neutron development.


Official Sub-Project List
-------------------------

The official source of all repositories that are a part of Neutron or another
official OpenStack project team is here:

    http://governance.openstack.org/reference/projects/neutron.html

We list the Neutron repositories, as well as other Neutron affiliated projects
here to provide references and note the functionality they provide.

Functionality legend
~~~~~~~~~~~~~~~~~~~~

- base: the base Neutron platform;
- bgp: BGP dynamic routing service plugin;
- client: API client implementation;
- core: a monolithic plugin that can implement API at multiple layers L3-L7;
- dashboard: Horizon dashboard integration;
- docker: a Docker network plugin that uses Neutron to provide networking services to Docker containers;
- fw: a Firewall service plugin;
- intent: a service plugin that provides a declarative API to realize networking;
- ipam: an IP address management driver;
- l2: a Layer 2 service;
- l3: a Layer 3 service plugin;
- lb: a Load Balancer service plugin;
- ml2: an ML2 mechanism driver;
- pd: prefix delegation;
- sfc: traffic steering based on traffic classification;
- vpn: a VPN service plugin;

Neutron projects
~~~~~~~~~~~~~~~~

This table shows the list of official Neutron repositories and their
functionality.

+-------------------------------+-----------------------+
| Name                          |    Functionality      |
+===============================+=======================+
| networking-bagpipe_           | ml2                   |
+-------------------------------+-----------------------+
| networking-bgpvpn_            | vpn                   |
+-------------------------------+-----------------------+
| networking-calico_            | ml2                   |
+-------------------------------+-----------------------+
| networking-l2gw_              | l2                    |
+-------------------------------+-----------------------+
| networking-midonet_           | core,ml2,l3,lb,fw     |
+-------------------------------+-----------------------+
| networking-odl_               | ml2,l3,lb,fw          |
+-------------------------------+-----------------------+
| networking-ofagent_           | ml2                   |
+-------------------------------+-----------------------+
| networking-onos_              | ml2,l3                |
+-------------------------------+-----------------------+
| networking-ovn_               | ml2,l3                |
+-------------------------------+-----------------------+
| networking-sfc_               | sfc                   |
+-------------------------------+-----------------------+
| neutron_                      | base,l2,ml2,core,l3   |
+-------------------------------+-----------------------+
| neutron-dynamic-routing_      | bgp                   |
+-------------------------------+-----------------------+
| neutron-fwaas_                | fw                    |
+-------------------------------+-----------------------+
| neutron-lbaas_                | lb,dashboard          |
| neutron-lbaas-dashboard_      |                       |
| octavia_                      |                       |
+-------------------------------+-----------------------+
| neutron-lib_                  | base                  |
+-------------------------------+-----------------------+
| neutron-vpnaas_               | vpn                   |
+-------------------------------+-----------------------+
| python-neutronclient_         | client                |
+-------------------------------+-----------------------+
| python-neutron-pd-driver_     | pd                    |
+-------------------------------+-----------------------+


Affiliated projects
~~~~~~~~~~~~~~~~~~~

This table shows the affiliated projects that integrate with Neutron,
in one form or another.  These projects typically leverage the pluggable
capabilities of Neutron, the Neutron API, or a combination of both.

+-------------------------------+-----------------------+
| Name                          |    Functionality      |
+===============================+=======================+
| dragonflow_                   | core                  |
+-------------------------------+-----------------------+
| kuryr_                        | docker                |
+-------------------------------+-----------------------+
| networking-ale-omniswitch_    | ml2                   |
+-------------------------------+-----------------------+
| networking-arista_            | ml2,l3                |
+-------------------------------+-----------------------+
| networking-bigswitch_         | ml2,core,l3           |
+-------------------------------+-----------------------+
| networking-brocade_           | ml2,l3                |
+-------------------------------+-----------------------+
| networking-cisco_             | core,ml2,l3,fw,vpn    |
+-------------------------------+-----------------------+
| networking-edge-vpn_          | vpn                   |
+-------------------------------+-----------------------+
| networking-fortinet_          | ml2,l3,fw             |
+-------------------------------+-----------------------+
| networking-fujitsu_           | ml2                   |
+-------------------------------+-----------------------+
| networking-hyperv_            | ml2                   |
+-------------------------------+-----------------------+
| networking-infoblox_          | ipam                  |
+-------------------------------+-----------------------+
| networking-mlnx_              | ml2                   |
+-------------------------------+-----------------------+
| networking-nec_               | core                  |
+-------------------------------+-----------------------+
| networking-ovs-dpdk_          | ml2                   |
+-------------------------------+-----------------------+
| networking-plumgrid_          | core                  |
+-------------------------------+-----------------------+
| networking-powervm_           | ml2                   |
+-------------------------------+-----------------------+
| networking-vsphere_           | ml2                   |
+-------------------------------+-----------------------+
| nuage-openstack-neutron_      | core                  |
+-------------------------------+-----------------------+
| vmware-nsx_                   | core                  |
+-------------------------------+-----------------------+

Project Teams FAQ
~~~~~~~~~~~~~~~~~

**Q: When talking about contributor overlap, what is a contributor?**

A Neutron contributor is someone who spends some portion of their time helping
with all of the things needed to run the Neutron project: bug triage, writing
and reviewing blueprints, writing and reviewing code, writing and reviewing
documentation, helping debug issues found by users or CI, and more.

**Q: Why choose contributor overlap over technical overlap?**

Technical overlap, or software qualities, are more difficult to pinpoint and
require a more extensive assessment from the PTL and the Neutron team, which
in turn has the danger of translating itself into a nearly full-time
policing/enforcement job. Wrongdoing will always be spotted, regardless of
whichever criteria is applied, and trusting known members of the team to do
the right thing should be an adequate safety net to preserve the sanity of
Neutron as a whole.

**Q: What does a sub-project gain as a part of the Neutron project team?**

A project under Neutron is no more an official part of OpenStack than another
OpenStack project team.  Projects under Neutron share some resources.  In
particular, they get managed backports, managed releases, managed CVEs, RFEs,
bugs, docs and everything that pertain the SDLC of the Neutron end-to-end
project.

**Q: Why is kuryr a separate project?**

Kuryr was started and incubated within the Neutron team.  However, it interfaces
with Neutron as a client of the Neutron API, so it makes sense to stand as an
independent project.

**Q: Why are several "advanced service" projects still included under Neutron?**

neutron-lbaas, neutron-fwaas, and neutron-vpnaas are all included under the
Neutron project team largely for historical reasons.  They were originally a
part of neutron itself and are still a part of the neutron deliverable in terms
of OpenStack governance.  Because of the deliverable inclusion, they should really
only be considered for a move on a release boundary.

**Q: Why is Octavia included under Neutron?**

neutron-lbaas, neutron-lbaas-dashboard, and Octavia are all considered a unit.
If we split one, we need to split them together.  We can't split these yet, as
they are a part of the official "neutron" deliverable.  This needs to be done on
a release boundary when the lbaas team is ready to do so.

.. _networking-ale-omniswitch:

ALE Omniswitch
++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-ale-omniswitch
* Launchpad: https://launchpad.net/networking-ale-omniswitch
* PyPI: https://pypi.python.org/pypi/networking-ale-omniswitch

.. _networking-arista:

Arista
++++++

* Git: https://git.openstack.org/cgit/openstack/networking-arista
* Launchpad: https://launchpad.net/networking-arista
* PyPI: https://pypi.python.org/pypi/networking-arista

.. _networking-bagpipe:

BaGPipe
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-bagpipe
* Launchpad: https://launchpad.net/networking-bagpipe
* PyPI: https://pypi.python.org/pypi/networking-bagpipe

.. _networking-bgpvpn:

BGPVPN
++++++

* Git: https://git.openstack.org/cgit/openstack/networking-bgpvpn
* Launchpad: https://launchpad.net/bgpvpn
* PyPI: https://pypi.python.org/pypi/networking-bgpvpn

.. _networking-bigswitch:

Big Switch Networks
+++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-bigswitch
* Launchpad: https://launchpad.net/networking-bigswitch
* PyPI: https://pypi.python.org/pypi/bsnstacklib

.. _networking-brocade:

Brocade
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-brocade
* Launchpad: https://launchpad.net/networking-brocade
* PyPI: https://pypi.python.org/pypi/networking-brocade

.. _networking-calico:

Calico
++++++

* Git: https://git.openstack.org/cgit/openstack/networking-calico
* Launchpad: https://launchpad.net/networking-calico
* PyPI: https://pypi.python.org/pypi/networking-calico

.. _networking-cisco:

Cisco
+++++

* Git: https://git.openstack.org/cgit/openstack/networking-cisco
* Launchpad: https://launchpad.net/networking-cisco
* PyPI: https://pypi.python.org/pypi/networking-cisco

.. _dragonflow:

DragonFlow
++++++++++

* Git: https://git.openstack.org/cgit/openstack/dragonflow
* Launchpad: https://launchpad.net/dragonflow
* PyPI: https://pypi.python.org/pypi/DragonFlow

.. _networking-edge-vpn:

Edge VPN
++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-edge-vpn
* Launchpad: https://launchpad.net/edge-vpn

.. _networking-fortinet:

Fortinet
++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-fortinet
* Launchpad: https://launchpad.net/networking-fortinet
* PyPI: https://pypi.python.org/pypi/networking-fortinet

.. _networking-fujitsu:

FUJITSU
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-fujitsu
* Launchpad: https://launchpad.net/networking-fujitsu
* PyPI: https://pypi.python.org/pypi/networking-fujitsu

.. _networking-hyperv:

Hyper-V
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-hyperv
* Launchpad: https://launchpad.net/networking-hyperv
* PyPI: https://pypi.python.org/pypi/networking-hyperv

.. _networking-infoblox:

Infoblox
++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-infoblox
* Launchpad: https://launchpad.net/networking-infoblox
* PyPI: https://pypi.python.org/pypi/networking-infoblox

.. _kuryr:

Kuryr
+++++

* Git: https://git.openstack.org/cgit/openstack/kuryr/
* Launchpad: https://launchpad.net/kuryr
* PyPI: https://pypi.python.org/pypi/kuryr/

.. _networking-l2gw:

L2 Gateway
++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-l2gw
* Launchpad: https://launchpad.net/networking-l2gw
* PyPI: https://pypi.python.org/pypi/networking-l2gw

.. _networking-midonet:

MidoNet
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-midonet
* Launchpad: https://launchpad.net/networking-midonet
* PyPI: https://pypi.python.org/pypi/networking-midonet

.. _networking-mlnx:

Mellanox
++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-mlnx
* Launchpad: https://launchpad.net/networking-mlnx

.. _networking-nec:

NEC
+++

* Git: https://git.openstack.org/cgit/openstack/networking-nec
* Launchpad: https://launchpad.net/networking-nec
* PyPI: https://pypi.python.org/pypi/networking-nec

.. _neutron:

Neutron
+++++++

* Git: https://git.openstack.org/cgit/openstack/neutron
* Launchpad: https://launchpad.net/neutron

.. _python-neutronclient:

Neutron Client
++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/python-neutronclient
* Launchpad: https://launchpad.net/python-neutronclient
* PyPI: https://pypi.python.org/pypi/python-neutronclient

.. _neutron-dynamic-routing:

Neutron Dynamic Routing
+++++++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/neutron-dynamic-routing
* Launchpad: https://launchpad.net/neutron

.. _neutron-fwaas:

Neutron FWaaS
+++++++++++++

* Git: https://git.openstack.org/cgit/openstack/neutron-fwaas
* Launchpad: https://launchpad.net/neutron

.. _neutron-lbaas:

Neutron LBaaS
+++++++++++++

* Git: https://git.openstack.org/cgit/openstack/neutron-lbaas
* Launchpad: https://launchpad.net/neutron

.. _neutron-lbaas-dashboard:

Neutron LBaaS Dashboard
+++++++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/neutron-lbaas-dashboard
* Launchpad: https://launchpad.net/neutron

.. _neutron-lib:

Neutron Library
+++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/neutron-lib
* Launchpad: https://launchpad.net/neutron

.. _python-neutron-pd-driver:

Neutron Prefix Delegation
+++++++++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/python-neutron-pd-driver
* Launchpad: https://launchpad.net/python-neutron-pd-driver
* PyPI: https://pypi.python.org/pypi/python-neutron-pd-driver

.. _neutron-vpnaas:

Neutron VPNaaS
++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/neutron-vpnaas
* Launchpad: https://launchpad.net/neutron

.. _nuage-openstack-neutron:

Nuage
+++++

* Git: https://github.com/nuagenetworks/nuage-openstack-neutron

.. _octavia:

Octavia
+++++++

* Git: https://git.openstack.org/cgit/openstack/octavia
* Launchpad: https://launchpad.net/octavia
* PyPI: https://pypi.python.org/pypi/octavia

.. _networking-odl:

OpenDayLight
++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-odl
* Launchpad: https://launchpad.net/networking-odl
* PyPI: https://pypi.python.org/pypi/networking-odl

.. _networking-ofagent:

OpenFlow Agent (ofagent)
++++++++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-ofagent
* Launchpad: https://launchpad.net/networking-ofagent
* PyPI: https://pypi.python.org/pypi/networking-ofagent

Note: The networking-ofagent project has been removed in the Newton cycle
      and the only stable branch is maintained until its EOL.

.. _networking-onos:

Open Network Operating System (onos)
++++++++++++++++++++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-onos
* Launchpad: https://launchpad.net/networking-onos
* PyPI: https://pypi.python.org/pypi/networking-onos

.. _networking-ovn:

Open Virtual Network
++++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-ovn
* Launchpad: https://launchpad.net/networking-ovn
* PyPI: https://pypi.python.org/pypi/networking-ovn

.. _networking-ovs-dpdk:

Open DPDK
+++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-ovs-dpdk
* Launchpad: https://launchpad.net/networking-ovs-dpdk
* PyPI: https://pypi.python.org/pypi/networking-ovs-dpdk

.. _networking-plumgrid:

PLUMgrid
++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-plumgrid
* Launchpad: https://launchpad.net/networking-plumgrid
* PyPI: https://pypi.python.org/pypi/networking-plumgrid

.. _networking-powervm:

PowerVM
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-powervm
* Launchpad: https://launchpad.net/networking-powervm
* PyPI: https://pypi.python.org/pypi/networking-powervm

.. _networking-sfc:

SFC
+++

* Git: https://git.openstack.org/cgit/openstack/networking-sfc
* Launchpad: https://launchpad.net/networking-sfc
* PyPI: https://pypi.python.org/pypi/networking-sfc

.. _networking-vsphere:

vSphere
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-vsphere
* Launchpad: https://launchpad.net/networking-vsphere
* PyPI: https://pypi.python.org/pypi/networking-vsphere

.. _vmware-nsx:

VMware NSX
++++++++++

* Git: https://git.openstack.org/cgit/openstack/vmware-nsx
* Launchpad: https://launchpad.net/vmware-nsx
* PyPI: https://pypi.python.org/pypi/vmware-nsx
