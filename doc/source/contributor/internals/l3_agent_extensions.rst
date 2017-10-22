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


L3 agent extensions
===================

L3 agent extensions are part of a generalized L2/L3 extension framework. See
:doc:`agent extensions <agent_extensions>`.

L3 agent extension API
----------------------

The L3 agent extension API object includes several methods that expose
router information to L3 agent extensions::

#. get_routers_in_project
#. get_router_hosting_port
#. is_router_in_namespace
#. get_router_info
