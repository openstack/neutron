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


L2 agent extensions
===================

All reference agents support common extension mechanism that allows to easily
reuse code between agents and to avoid the need to patch an agent for each new
core resource extension. Those extensions can be especially interesting to
third parties that don't want to maintain their code in Neutron tree.

Extensions are referenced through stevedore entry points defined under
neutron.agent.l2.extensions namespace. On each port event, handle_port is
triggered by the agent.

* neutron.agent.l2.agent_extension:
  This module defines an abstract extension interface.

* neutron.agent.l2.extensions.manager:
  This module contains a manager that allows to register multiple extensions,
  and passes handle_port events down to all enabled extensions.


Agent API object
----------------

Every agent can pass a so-called agent API object into extensions to expose
some of its internals to them in controlled way.

If an extension is interested in using the object, it should define
consume_api() method that will receive the object before extension's
initialize() method is called by the extension manager.

This agent API object is part of public Neutron interface for third parties.
All changes to the interface will be managed in backwards compatible way.

At the moment, only Open vSwitch agent provides an agent API object to
extensions.

Open vSwitch agent API
~~~~~~~~~~~~~~~~~~~~~~

* neutron.plugins.ml2.drivers.openvswitch.agent.ovs_agent_extension_api

Open vSwitch agent API object includes two methods that return wrapped and
hardened bridge objects with cookie values allocated for calling extensions.

#. request_int_br
#. request_tun_br

Bridge objects returned by those methods already have new default cookie values
allocated for extension flows. All flow management methods (add_flow, mod_flow,
...) enforce those allocated cookies.

Extensions are able to use those wrapped bridge objects to set their own flows,
while the agent relies on the collection of those allocated values when
cleaning up stale flows from the previous agent session::

  +-----------+
  | Agent API +--------------------------------------------------+
  +-----+-----+                                                  |
        |                                   +-----------+        |
        |1                               +--+ Extension +--+     |
        |                                |  +-----------+  |     |
  +---+-+-+---+  2  +--------------+  3  |                 |  4  |
  |   Agent   +-----+ Ext. manager +-----+--+   ....    +--+-----+
  +-----------+     +--------------+     |                 |
                                         |  +-----------+  |
                                         +--+ Extension +--+
                                            +-----------+

Interactions with the agent API object are in the following order::

#1 the agent initializes the agent API object (bridges, other internal state)
#2 the agent passes the agent API object into the extension manager
#3 the manager passes the agent API object into each extension
#4 an extension calls the new agent API object method to receive bridge wrappers with cookies allocated.

Call #4 also registers allocated cookies with the agent bridge objects.
