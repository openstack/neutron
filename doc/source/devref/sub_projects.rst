Official Sub-Projects
=====================

Neutron has a set of official sub-projects.  These projects are recognized as a
part of the overall Neutron project.

Inclusion Process
-----------------

The process for proposing the move of a repo into openstack/ and under
the Neutron project is to propose a patch to the openstack/governance
repository.  For example, to propose moving networking-foo, one
would add the following entry under Neutron in reference/projects.yaml::

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

Responsibilities
----------------

All affected repositories already have their own review teams.  The
sub-team working on the sub-project is entirely responsible for
day-to-day development.  That includes reviews, bug tracking, and
working on testing.

By being included, the project accepts oversight by the TC as a part of
being in OpenStack, and also accepts oversight by the Neutron PTL.

Inclusion Criteria
------------------

As mentioned before, the Neutron PTL must approve the inclusion of each
additional repository under the Neutron project.  That evaluation will be
primarily based on the new project requirements used for all new OpenStack
projects for the criteria that is applicable:

    http://governance.openstack.org/reference/new-projects-requirements.html

Official Sub-Project List
-------------------------

The official source of all repositories that exist under the Neutron project is:

    http://governance.openstack.org/reference/projects/neutron.html

The sub-projects are also listed here for convenience and as a place to provide
some additional metadata about them:

+-------------------------------+-----------------------+
| Name                          |    Functionality      |
+===============================+=======================+
|                               |                       |
+-------------------------------+-----------------------+

Affiliated projects
===================

Affiliated projects are related to Neutron in some way, but are not official
sub-projects of Neutron.

This table shows the unofficial affiliated projects that integrate with Neutron,
in one form or another. These projects typically leverage the pluggable
capabilities of Neutron, the Neutron API, or a combination of both.

+-------------------------------+-----------------------+
| Name                          |    Functionality      |
+===============================+=======================+
| dragonflow_                   |           l3          |
+-------------------------------+-----------------------+
| group-based-policy_           |         intent        |
+-------------------------------+-----------------------+
| networking-arista_            |         ml2,l3        |
+-------------------------------+-----------------------+
| networking-bagpipe-l2_        |          vpn          |
+-------------------------------+-----------------------+
| networking-bgpvpn_            |          vpn          |
+-------------------------------+-----------------------+
| networking-bigswitch_         |      ml2,core,l3      |
+-------------------------------+-----------------------+
| networking-brocade_           |        ml2,l3         |
+-------------------------------+-----------------------+
| networking-cisco_             |  core,ml2,l3,fw,vpn   |
+-------------------------------+-----------------------+
| networking-edge-vpn_          |          vpn          |
+-------------------------------+-----------------------+
| networking-hyperv_            |          ml2          |
+-------------------------------+-----------------------+
| networking-ibm_               |         ml2,l3        |
+-------------------------------+-----------------------+
| networking-l2gw_              |         l2            |
+-------------------------------+-----------------------+
| networking-metaplugin_        |         core          |
+-------------------------------+-----------------------+
| networking-midonet_           |        core,lb        |
+-------------------------------+-----------------------+
| networking-mlnx_              |          ml2          |
+-------------------------------+-----------------------+
| networking-nec_               |         core          |
+-------------------------------+-----------------------+
| nuage-openstack-neutron_      |         core          |
+-------------------------------+-----------------------+
| networking-odl_               |      ml2,l3,lb,fw     |
+-------------------------------+-----------------------+
| networking-ofagent_           |          ml2          |
+-------------------------------+-----------------------+
| networking-ovn_               |          ml2          |
+-------------------------------+-----------------------+
| networking-ovs-dpdk_          |          ml2          |
+-------------------------------+-----------------------+
| networking-plumgrid_          |          core         |
+-------------------------------+-----------------------+
| networking-portforwarding_    |          l3           |
+-------------------------------+-----------------------+
| neutron-powervm_              |          ml2          |
+-------------------------------+-----------------------+
| networking-vsphere_           |          ml2          |
+-------------------------------+-----------------------+
| vmware-nsx_                   |          core         |
+-------------------------------+-----------------------+
| octavia_                      |          lb           |
+-------------------------------+-----------------------+

Functionality legend
--------------------

- l2: a Layer 2 service;
- ml2: an ML2 mechanism driver;
- core: a monolithic plugin that can implement API at multiple layers L3-L7;
- l3: a Layer 3 service plugin;
- fw: a Firewall service plugin;
- vpn: a VPN service plugin;
- lb: a Load Balancer service plugin;
- intent: a service plugin that provides a declarative API to realize networking;

.. _networking-arista:

Arista
------

* Git: https://git.openstack.org/cgit/stackforge/networking-arista
* Launchpad: https://launchpad.net/networking-arista
* Pypi: https://pypi.python.org/pypi/networking-arista

.. _networking-bagpipe-l2:

BaGPipe
-------

* Git: https://git.openstack.org/cgit/stackforge/networking-bagpipe-l2
* Launchpad: https://launchpad.net/bagpipe-l2
* Pypi: https://pypi.python.org/pypi/bagpipe-l2

.. _networking-bgpvpn:

BGPVPN
-------

* Git: https://git.openstack.org/cgit/openstack/networking-bgpvpn

.. _networking-bigswitch:

Big Switch Networks
-------------------

* Git: https://git.openstack.org/cgit/stackforge/networking-bigswitch
* Pypi: https://pypi.python.org/pypi/bsnstacklib

.. _networking-brocade:

Brocade
-------

* Git: https://git.openstack.org/cgit/stackforge/networking-brocade
* Launchpad: https://launchpad.net/networking-brocade
* PyPI: https://pypi.python.org/pypi/networking-brocade

.. _networking-cisco:

Cisco
-----

* Git: https://git.openstack.org/cgit/stackforge/networking-cisco
* Launchpad: https://launchpad.net/networking-cisco
* PyPI: https://pypi.python.org/pypi/networking-cisco

.. _dragonflow:

DragonFlow
----------

* Git: https://git.openstack.org/cgit/openstack/dragonflow
* Launchpad: https://launchpad.net/dragonflow
* PyPi: https://pypi.python.org/pypi/DragonFlow

.. _networking-edge-vpn:

Edge VPN
--------

* Git: https://git.openstack.org/cgit/stackforge/networking-edge-vpn
* Launchpad: https://launchpad.net/edge-vpn

.. _networking-hyperv:

Hyper-V
-------

* Git: https://git.openstack.org/cgit/stackforge/networking-hyperv
* Launchpad: https://launchpad.net/networking-hyperv
* PyPi: https://pypi.python.org/pypi/networking-hyperv

.. _group-based-policy:

Group Based Policy
------------------

* Git: https://git.openstack.org/cgit/stackforge/group-based-policy
* Launchpad: https://launchpad.net/group-based-policy
* PyPi: https://pypi.python.org/pypi/group-based-policy

.. _networking-ibm:

IBM SDNVE
---------

* Git: https://git.openstack.org/cgit/stackforge/networking-ibm
* Launchpad: https://launchpad.net/networking-ibm

.. _networking-l2gw:

L2 Gateway
----------

* Git: https://git.openstack.org/cgit/openstack/networking-l2gw
* Launchpad: https://launchpad.net/networking-l2gw

.. _networking-metaplugin:

Metaplugin
----------

* Git: https://github.com/ntt-sic/networking-metaplugin

.. _networking-midonet:

MidoNet
-------

* Git: https://git.openstack.org/cgit/openstack/networking-midonet
* Launchpad: https://launchpad.net/networking-midonet
* PyPI: https://pypi.python.org/pypi/networking-midonet

.. _networking-mlnx:

Mellanox
--------

* Git: https://git.openstack.org/cgit/stackforge/networking-mlnx
* Launchpad: https://launchpad.net/networking-mlnx

.. _networking-nec:

NEC
---

* Git: https://git.openstack.org/cgit/stackforge/networking-nec
* Launchpad: https://launchpad.net/networking-nec
* PyPI: https://pypi.python.org/pypi/networking-nec

.. _nuage-openstack-neutron:

Nuage
-----

* Git: https://github.com/nuage-networks/nuage-openstack-neutron

.. _networking-odl:

OpenDayLight
------------

* Git: https://git.openstack.org/cgit/openstack/networking-odl
* Launchpad: https://launchpad.net/networking-odl

.. _networking-ofagent:

OpenFlow Agent (ofagent)
------------------------

* Git: https://git.openstack.org/cgit/openstack/networking-ofagent
* Launchpad: https://launchpad.net/networking-ofagent
* PyPI: https://pypi.python.org/pypi/networking-ofagent

.. _networking-ovn:

Open Virtual Network
--------------------

* Git: https://git.openstack.org/cgit/openstack/networking-ovn
* Launchpad: https://launchpad.net/networking-ovn
* PyPI: https://pypi.python.org/pypi/networking-ovn

.. _networking-ovs-dpdk:

Open DPDK
---------

* Git: https://git.openstack.org/cgit/stackforge/networking-ovs-dpdk
* Launchpad: https://launchpad.net/networking-ovs-dpdk

.. _networking-plumgrid:

PLUMgrid
--------

* Git: https://git.openstack.org/cgit/stackforge/networking-plumgrid
* Launchpad: https://launchpad.net/networking-plumgrid
* PyPI: https://pypi.python.org/pypi/networking-plumgrid

.. _neutron-powervm:

PowerVM
-------

* Git: https://git.openstack.org/cgit/stackforge/neutron-powervm
* Launchpad: https://launchpad.net/neutron-powervm
* PyPI: https://pypi.python.org/pypi/neutron-powervm

.. _networking-portforwarding:

PortForwarding
--------------

* Git: https://git.openstack.org/cgit/stackforge/networking-portforwarding
* Launchpad: https://launchpad.net/networking-portforwarding

.. _networking-vsphere:

vSphere
-------

* Git: https://git.openstack.org/cgit/stackforge/networking-vsphere
* Launchpad: https://launchpad.net/networking-vsphere

.. _vmware-nsx:

VMware NSX
----------

* Git: https://git.openstack.org/cgit/openstack/vmware-nsx
* Launchpad: https://launchpad.net/vmware-nsx
* PyPI: https://pypi.python.org/pypi/vmware-nsx

.. _octavia:

Octavia
-------

* Git: https://git.openstack.org/cgit/openstack/octavia
* Launchpad: https://launchpad.net/octavia
