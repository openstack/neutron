Services and agents
===================

A usual Neutron setup consists of multiple services and agents running on one
or multiple nodes (though some exotic setups potentially may not need any
agents). Each of those services provides some of the networking or API
services. Among those of special interest:

#. neutron-server that provides API endpoints and serves as a single point of
   access to the database. It usually runs on nodes called Controllers.
#. Layer2 agent that can utilize Open vSwitch, Linuxbridge or other vendor
   specific technology to provide network segmentation and isolation for tenant
   networks. The L2 agent should run on every node where it is deemed
   responsible for wiring and securing virtual interfaces (usually both Compute
   and Network nodes).
#. Layer3 agent that runs on Network node and provides East-West and
   North-South routing plus some advanced services such as FWaaS or VPNaaS.

For the purpose of this document, we call all services, servers and agents that
run on any node as just "services".


Entry points
------------

Entry points for services are defined in setup.cfg under "console_scripts"
section.  Those entry points should generally point to main() functions located
under neutron/cmd/... path.

Note: some existing vendor/plugin agents still maintain their entry points in
other locations. Developers responsible for those agents are welcome to apply
the guideline above.


Interacting with Eventlet
-------------------------

Neutron extensively utilizes the eventlet library to provide asynchronous
concurrency model to its services. To utilize it correctly, the following
should be kept in mind.

If a service utilizes the eventlet library, then it should not call
eventlet.monkey_patch() directly but instead maintain its entry point main()
function under neutron/cmd/eventlet/... If that is the case, the standard
Python library will be automatically patched for the service on entry point
import (monkey patching is done inside `python package file
<http://git.openstack.org/cgit/openstack/neutron/tree/neutron/cmd/eventlet/__init__.py>`_).

Note: an entry point 'main()' function may just be an indirection to a real
callable located elsewhere, as is done for reference services such as DHCP, L3
and the neutron-server.

For more info on the rationale behind the code tree setup, see `the
corresponding cross-project spec <https://review.openstack.org/154642>`_.
