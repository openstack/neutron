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


Agent Extensions
================

All reference agents utilize a common extension mechanism that allows for the
introduction and enabling of a core resource extension without needing to
change agent code. This mechanism allows multiple agent extensions to be run by
a single agent simultaneously.  The mechanism may be especially interesting to
third parties whose extensions lie outside the neutron tree.

Under this framework, an agent may expose its API to each of its extensions
thereby allowing an extension to access resources internal to the agent. At
layer 2, for instance, upon each port event the agent is then able to trigger a
handle_port method in its extensions.

Interactions with the agent API object are in the following order:

#. The agent initializes the agent API object.
#. The agent passes the agent API object into the extension manager.
#. The manager passes the agent API object into each extension.
#. An extension calls the new agent API object method to receive, for instance,
   bridge wrappers with cookies allocated.

::

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

Each extension is referenced through a stevedore entry point defined within a
specific namespace. For example, L2 extensions are referenced through the
neutron.agent.l2.extensions namespace.

The relevant modules are:

* neutron_lib.agent.extension:
  This module defines an abstract extension interface for all agent
  extensions across L2 and L3.

* neutron_lib.agent.l2_extension:
* neutron_lib.agent.l3_extension:
  These modules subclass
  neutron_lib.agent.extension.AgentExtension and define a
  layer-specific abstract extension interface.

* neutron.agent.agent_extensions_manager:
  This module contains a manager that allows extensions to load themselves at
  runtime.

* neutron.agent.l2.l2_agent_extensions_manager:
* neutron.agent.l3.l3_agent_extensions_manager:
  Each of these modules passes core resource events to loaded extensions.


Agent API object
----------------

Every agent can pass an "agent API object" into its extensions in order to
expose its internals to them in a controlled way. To accommodate different
agents, each extension may define a consume_api() method that will receive
this object.

This agent API object is part of neutron's public interface for third parties.
All changes to the interface will be managed in a backwards-compatible way.

At this time, on the L2 side, only the L2 Open vSwitch agent provides an agent
API object to extensions. See :doc:`L2 agent extensions <l2_agent_extensions>`.
For L3, see :doc:`L3 agent extensions <l3_agent_extensions>`.

The relevant modules are:

* neutron_lib.agent.extension
* neutron_lib.agent.l2_extension
* neutron_lib.agent.l3_extension
* neutron.agent.agent_extensions_manager
* neutron.agent.l2.l2_agent_extensions_manager
* neutron.agent.l3.l3_agent_extensions_manager
