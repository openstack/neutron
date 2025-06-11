.. _ovn_agent:

OVN agent
=========

The OVN agent is a service that could be executed in any node running the
ovn-controller service. This agent provides additional functionalities not
provided by OVN; for example, a metadata proxy between the virtual machines
and the Nova metadata service. This agent will replace the need of
the OVN metadata agent.


OVN and OVS database connectivity
---------------------------------

The OVN agent can access the local OVS database where the service is
running. It also has access to the Northbound and Southbound OVN databases. The
connection strings to these databases are defined in the agent configuration
file:

.. code-block:: console

    [ovn]
    ovn_nb_connection = tcp:192.168.10.100:6641
    ovn_sb_connection = tcp:192.168.10.100:6642
    [ovs]
    ovsdb_connection = tcp:127.0.0.1:6640


Plugable extensions
-------------------

The OVN agent provides functionalities via extensions. When the agent is
started, the ``OVNAgentExtensionManager`` instance loads the configured
extensions. The extensions are defined in the stevedore entry points, under
the section "neutron.agent.ovn.extensions". The extensions are defined in the
agent configuration file in the "extensions" parameter:

.. code-block:: console

    [agent]
    extensions = metadata


In ``devstack``, the ``[agent]extensions`` configuration parameter is set by
``OVN_AGENT_EXTENSIONS``.

Each extension will inherit from ``OVNAgentExtension``, which provides the API
for an OVN agent extension. The extensions are loaded in two steps:

* Initialization: this phase involves the call of
  ``OVNAgentExtension.consume_api`` and ``OVNAgentExtension.initialize`` (in
  this order). The first one assigns the extension API to the instance. In this
  case, the OVN agent has a specific instance ``OVNAgentExtensionAPI`` that
  gives to the extensions the needed access to OVS and OVN databases, using the
  same IDL instance. The second one is not currently used in the base class;
  it could be used, for example as in the metadata extension, to spawn the
  process monitor.
* Start: in this phase, the OVN and OVS database connections are established
  and can be accessed. The extension manager will call each extension
  ``OVNAgentExtension.start`` method.


Each extension should define a set of OVS, OVN Northbound and OVN Southbound
tables to monitor, and a set of events related to these databases. The OVN
agent will create the corresponding IDL connections using the conjunction of
these tables and events.


Event-driven service
--------------------

The OVN agent is a ``oslo_service.service.Service`` type class, that is
launched when the script is executed. Once initialized, the service is waiting
for new events that will trigger actions. As mentioned in the previous section,
each extension will subscribe to a set of events from the OVN and OVS
databases; these events will trigger a set of actions executed on the OVN
agent.


Zuul CI testing
---------------

In order to enable this new agent, it is needed:

* To disable the default OVN Metadata agent (devstack service
  ``q-ovn-metadata-agent``).
* To enable the OVN agent (devstack service ``q-ovn-agent``).

Check the Neutron CI job ``neutron-tempest-plugin-ovn`` definition and
`[OVN] Use the OVN agent in "neutron-tempest-plugin-ovn"
<https://review.opendev.org/c/openstack/neutron-tempest-plugin/+/909860>`_
for more information.
