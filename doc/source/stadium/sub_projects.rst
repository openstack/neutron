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


Official Sub-Projects
=====================

Neutron has a set of official sub-projects.  These projects are recognized as a
part of the overall Neutron project.

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
additional repository under the Neutron project.  That evaluation will be
primarily based on the new project requirements used for all new OpenStack
projects for the criteria that is applicable:

    http://governance.openstack.org/reference/new-projects-requirements.html

Official Sub-Project List
-------------------------

The official source of all repositories that are a part of Neutron or another
official OpenStack project team is here:

    http://governance.openstack.org/reference/projects/neutron.html

We list the Neutron repositories, as well as other Neutron affiliated projects
here to provide references and note the functionality they provide.

Functionality legend
~~~~~~~~~~~~~~~~~~~~

- base: the base Neutron platform
- client: API client implementation
- core: a monolithic plugin that can implement API at multiple layers L3-L7;
- dashboard: Horizon dashboard integration
- docker: a Docker network plugin that uses Neutron to provide networking services to Docker containers;
- fw: a Firewall service plugin;
- intent: a service plugin that provides a declarative API to realize networking;
- ipam: an IP address management driver;
- l2: a Layer 2 service;
- l3: a Layer 3 service plugin;
- lb: a Load Balancer service plugin;
- ml2: an ML2 mechanism driver;
- sfc; traffic steering based on traffic classification
- vpn: a VPN service plugin;

Neutron projects
~~~~~~~~~~~~~~~~

This table shows the list of official Neutron repositories and their
functionality.

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
| networking-bagpipe_           | ml2                   |
+-------------------------------+-----------------------+
| networking-bgpvpn_            | vpn                   |
+-------------------------------+-----------------------+
| networking-calico_            | ml2                   |
+-------------------------------+-----------------------+
| networking-cisco_             | core,ml2,l3,fw,vpn    |
+-------------------------------+-----------------------+
| networking-fujitsu_           | ml2                   |
+-------------------------------+-----------------------+
| networking-hyperv_            | ml2                   |
+-------------------------------+-----------------------+
| networking-infoblox_          | ipam                  |
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
| networking-ovn_               | core                  |
+-------------------------------+-----------------------+
| networking-plumgrid_          | core                  |
+-------------------------------+-----------------------+
| networking-powervm_           | ml2                   |
+-------------------------------+-----------------------+
| networking-sfc_               | sfc                   |
+-------------------------------+-----------------------+
| networking-vsphere_           | ml2                   |
+-------------------------------+-----------------------+
| neutron_                      | base,l2,ml2,core,l3   |
+-------------------------------+-----------------------+
| neutron-lbaas_                | lb,dashboard          |
| neutron-lbaas-dashboard_      |                       |
| octavia_                      |                       |
+-------------------------------+-----------------------+
| neutron-fwaas_                | fw                    |
+-------------------------------+-----------------------+
| neutron-lib_                  | base                  |
+-------------------------------+-----------------------+
| neutron-vpnaas_               | vpn                   |
+-------------------------------+-----------------------+
| python-neutronclient_         | client                |
+-------------------------------+-----------------------+
| vmware-nsx_                   | core                  |
+-------------------------------+-----------------------+


Affiliated projects
~~~~~~~~~~~~~~~~~~~

This table shows the affiliated projects that integrate with Neutron,
in one form or another.  These projects typically leverage the pluggable
capabilities of Neutron, the Neutron API, or a combination of both.

+-------------------------------+-----------------------+
| Name                          |    Functionality      |
+===============================+=======================+
| networking-bigswitch_         | ml2,core,l3           |
+-------------------------------+-----------------------+
| networking-brocade_           | ml2,l3                |
+-------------------------------+-----------------------+
| networking-edge-vpn_          | vpn                   |
+-------------------------------+-----------------------+
| networking-mlnx_              | ml2                   |
+-------------------------------+-----------------------+
| networking-nec_               | core                  |
+-------------------------------+-----------------------+
| nuage-openstack-neutron_      | core                  |
+-------------------------------+-----------------------+
| networking-ovs-dpdk_          | ml2                   |
+-------------------------------+-----------------------+

.. _networking-ale-omniswitch:

ALE Omniswitch
++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-ale-omniswitch
* Launchpad: https://launchpad.net/networking-ale-omniswitch
* Pypi: https://pypi.python.org/pypi/networking-ale-omniswitch

.. _networking-arista:

Arista
++++++

* Git: https://git.openstack.org/cgit/openstack/networking-arista
* Launchpad: https://launchpad.net/networking-arista
* Pypi: https://pypi.python.org/pypi/networking-arista

.. _networking-bagpipe:

BaGPipe
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-bagpipe

.. _networking-bgpvpn:

BGPVPN
++++++

* Git: https://git.openstack.org/cgit/openstack/networking-bgpvpn

.. _networking-bigswitch:

Big Switch Networks
+++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-bigswitch
* Pypi: https://pypi.python.org/pypi/bsnstacklib

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

.. _neutron-vpnaas:

Neutron VPNaaS
++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/neutron-vpnaas
* Launchpad: https://launchpad.net/neutron

.. _nuage-openstack-neutron:

Nuage
+++++

* Git: https://github.com/nuagenetworks/nuage-openstack-neutron

.. _networking-odl:

OpenDayLight
++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-odl
* Launchpad: https://launchpad.net/networking-odl

.. _networking-ofagent:

OpenFlow Agent (ofagent)
++++++++++++++++++++++++

* Git: https://git.openstack.org/cgit/openstack/networking-ofagent
* Launchpad: https://launchpad.net/networking-ofagent
* PyPI: https://pypi.python.org/pypi/networking-ofagent

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

.. _networking-vsphere:

vSphere
+++++++

* Git: https://git.openstack.org/cgit/openstack/networking-vsphere
* Launchpad: https://launchpad.net/networking-vsphere

.. _vmware-nsx:

VMware NSX
++++++++++

* Git: https://git.openstack.org/cgit/openstack/vmware-nsx
* Launchpad: https://launchpad.net/vmware-nsx
* PyPI: https://pypi.python.org/pypi/vmware-nsx

.. _octavia:

Octavia
+++++++

* Git: https://git.openstack.org/cgit/openstack/octavia
* Launchpad: https://launchpad.net/octavia
