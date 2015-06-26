Guided Tour: The Neutron Security Group API
===========================================

https://wiki.openstack.org/wiki/Neutron/SecurityGroups


API Extension
-------------

The API extension is the 'front' end portion of the code, which handles defining a `REST-ful API`_, which is used by tenants.


.. _`REST-ful API`: https://git.openstack.org/cgit/openstack/neutron/tree/neutron/extensions/securitygroup.py


Database API
------------

The Security Group API extension adds a number of `methods to the database layer`_ of Neutron

.. _`methods to the database layer`: https://git.openstack.org/cgit/openstack/neutron/tree/neutron/db/securitygroups_db.py

Agent RPC
---------

This portion of the code handles processing requests from tenants, after they have been stored in the database. It involves messaging all the L2 agents
running on the compute nodes, and modifying the IPTables rules on each hypervisor.


* `Plugin RPC classes <https://git.openstack.org/cgit/openstack/neutron/tree/neutron/db/securitygroups_rpc_base.py>`_

  * `SecurityGroupServerRpcMixin <https://git.openstack.org/cgit/openstack/neutron/tree/neutron/db/securitygroups_rpc_base.py#39>`_ - defines the RPC API that the plugin uses to communicate with the agents running on the compute nodes
  * SecurityGroupServerRpcMixin  -  Defines the API methods used to fetch data from the database, in order to return responses to agents via the RPC API

* `Agent RPC classes <https://git.openstack.org/cgit/openstack/neutron/tree/neutron/agent/securitygroups_rpc.py>`_

  * The SecurityGroupServerRpcApi defines the API methods that can be called by agents, back to the plugin that runs on the Neutron controller
  * The SecurityGroupAgentRpcCallbackMixin defines methods that a plugin uses to call back to an agent after performing an action called by an agent.


IPTables Driver
---------------

*  ``prepare_port_filter`` takes a ``port`` argument, which is a ``dictionary`` object that contains information about the port - including the ``security_group_rules``

*  ``prepare_port_filter`` `appends the port to an internal dictionary  <https://git.openstack.org/cgit/openstack/neutron/tree/neutron/agent/linux/iptables_firewall.py#L60>`_, ``filtered_ports`` which is used to track the internal state.

* Each security group has a `chain <http://www.thegeekstuff.com/2011/01/iptables-fundamentals/>`_ in Iptables.

* The ``IptablesFirewallDriver`` has a method to `convert security group rules into iptables statements <https://git.openstack.org/cgit/openstack/neutron/tree/neutron/agent/linux/iptables_firewall.py#L248>`_
