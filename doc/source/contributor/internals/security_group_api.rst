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


Security Group API
==================

https://wiki.openstack.org/wiki/Neutron/SecurityGroups


API Extension
-------------

The API extension is the 'front' end portion of the code, which handles defining a `REST-ful API`_, which is used by projects.


.. _`REST-ful API`: https://opendev.org/openstack/neutron/src/neutron/extensions/securitygroup.py


Database API
------------

The Security Group API extension adds a number of `methods to the database layer`_ of Neutron

.. _`methods to the database layer`: https://opendev.org/openstack/neutron/src/neutron/db/securitygroups_db.py

Agent RPC
---------

This portion of the code handles processing requests from projects, after they have been stored in the database. It involves messaging all the L2 agents
running on the compute nodes, and modifying the IPTables rules on each hypervisor.


* `Plugin RPC classes <https://opendev.org/openstack/neutron/src/neutron/db/securitygroups_rpc_base.py>`_

  * `SecurityGroupServerRpcMixin <https://opendev.org/openstack/neutron/src/neutron/db/securitygroups_rpc_base.py>`_ - defines the RPC API that the plugin uses to communicate with the agents running on the compute nodes
  * SecurityGroupServerRpcMixin  -  Defines the API methods used to fetch data from the database, in order to return responses to agents via the RPC API

* `Agent RPC classes <https://opendev.org/openstack/neutron/src/neutron/api/rpc/handlers/securitygroups_rpc.py>`_

  * The SecurityGroupServerRpcApi defines the API methods that can be called by agents, back to the plugin that runs on the Neutron controller
  * The SecurityGroupAgentRpcCallbackMixin defines methods that a plugin uses to call back to an agent after performing an action called by an agent.


IPTables Driver
---------------

*  ``prepare_port_filter`` takes a ``port`` argument, which is a ``dictionary`` object that contains information about the port - including the ``security_group_rules``

*  ``prepare_port_filter`` appends the port to an internal dictionary, ``filtered_ports`` which is used to track the internal state.

* Each security group has a `chain <http://www.thegeekstuff.com/2011/01/iptables-fundamentals/>`_ in Iptables.

* The ``IptablesFirewallDriver`` has a method to convert security group rules into iptables statements.
