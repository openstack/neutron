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


Services and agents
===================

A usual Neutron setup consists of multiple services and agents running on one
or multiple nodes (though some exotic setups potentially may not need any
agents). Each of those services provides some of the networking or API
services. Among those of special interest:

#. neutron-server that provides API endpoints and serves as a single point of
   access to the database. It usually runs on nodes called Controllers.
#. Layer2 agent that can utilize Open vSwitch, Linuxbridge or other vendor
   specific technology to provide network segmentation and isolation for project
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
<http://opendev.org/openstack/neutron/tree/neutron/cmd/eventlet/__init__.py>`_).

Note: an entry point 'main()' function may just be an indirection to a real
callable located elsewhere, as is done for reference services such as DHCP, L3
and the neutron-server.

For more info on the rationale behind the code tree setup, see `the
corresponding cross-project spec <https://review.opendev.org/154642>`_.


Connecting to the Database
--------------------------

Only the neutron-server connects to the neutron database. Agents may never
connect directly to the database, as this would break the ability to do rolling
upgrades.

Configuration Options
---------------------

In addition to database access, configuration options are segregated between
neutron-server and agents. Both services and agents may load the main
```neutron.conf``` since this file should contain the oslo.messaging
configuration for internal Neutron RPCs and may contain host specific
configuration such as file paths. In addition ```neutron.conf``` contains the
database, Keystone, and Nova credentials and endpoints strictly for
neutron-server to use.

In addition neutron-server may load a plugin specific configuration file, yet
the agents should not. As the plugin configuration is primarily site wide
options and the plugin provides the persistence layer for Neutron, agents
should be instructed to act upon these values via RPC.

Each individual agent may have its own configuration file. This file should be
loaded after the main ```neutron.conf``` file, so the agent configuration takes
precedence. The agent specific configuration may contain configurations which
vary between hosts in a Neutron deployment such as the ``local_ip`` for an L2
agent. If any agent requires access to additional external services beyond the
neutron RPC, those endpoints should be defined in the agent-specific
configuration file (e.g. nova metadata for metadata agent).
