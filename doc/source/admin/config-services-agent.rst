.. _config-services-agent:

===================
Services and agents
===================

A usual neutron setup consists of multiple services and agents running on one
or multiple nodes (though some setups may not need any agents).
Each of these services provide some of the networking or API services.
Among those of special interest are:

#. The neutron-server that provides API endpoints and serves as a single point
   of access to the database. It usually runs on the controller nodes.
#. Layer2 agent that can utilize Open vSwitch, Linux Bridge or other
   vendor-specific technology to provide network segmentation and isolation
   for project networks.
   The L2 agent should run on every node where it is deemed
   responsible for wiring and securing virtual interfaces (usually both
   compute and network nodes).
#. Layer3 agent that runs on network node and provides east-west and
   north-south routing plus some advanced services such as FWaaS or VPNaaS.

Configuration options
~~~~~~~~~~~~~~~~~~~~~

The neutron configuration options are segregated between
neutron-server and agents. Both services and agents may load the main
``neutron.conf`` since this file should contain the oslo.messaging
configuration for internal neutron RPCs and may contain host specific
configuration, such as file paths. The ``neutron.conf`` contains the
database, keystone, nova credentials, and endpoints strictly for
neutron-server to use.

In addition, neutron-server may load a plugin-specific configuration file, yet
the agents should not. As the plugin configuration is primarily site wide
options and the plugin provides the persistence layer for neutron, agents
should be instructed to act upon these values through RPC.

Each individual agent may have its own configuration file. This file should be
loaded after the main ``neutron.conf`` file, so the agent configuration takes
precedence. The agent-specific configuration may contain configurations which
vary between hosts in a neutron deployment such as the ``local_ip`` for an L2
agent. If any agent requires access to additional external services beyond the
neutron RPC, those endpoints should be defined in the agent-specific
configuration file (for example, nova metadata for metadata agent).

Agent's admin state specific config options
-------------------------------------------

When creating a new agent the ``admin_state_up`` field will be set to the
value of ``enable_new_agents`` config option, the default value of this config
option is ``true``:

.. code-block:: ini

    [DEFAULT]
    enable_new_agents = true

It is possible to set the ``admin_state_up`` value of an agent to ``False``
via the API, or CLI:

.. code-block:: console

    $ openstack network agent set agent-uuid --disable

The effect of this varies by agent type:

L2 agents
~~~~~~~~~

The ``admin_state_up`` field of the agent in the Neutron database is set to
``False``, but the agent is still capable of binding ports.
This is true for openvswitch-agent, linuxbridge-agent, and sriov-agent.

.. note::

    In case of OVN based deployment Neutron doesn't keep track of OVN
    controllers in the ``agents`` db table, so setting the ``admin_state_up``
    is not allowed as Neutron has no control over OVN entities.
    The possiblity to delete an OVN agent via Neutron REST API, is to clean
    up bad chassis information.

Metadata agent
~~~~~~~~~~~~~~

Setting ``admin_state_up`` to False has no effect to the Metadata agent.

DHCP agent
~~~~~~~~~~

DHCP agent scheduler will schedule networks to agents whose ``admin_state_up``
is ``True``.

L3 agent
~~~~~~~~

L3 scheduler will schedule routers to L3 agents whose ``admin_state_up`` field
is ``True``.

External processes run by agents
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some neutron agents, like DHCP, Metadata or L3, often run external
processes to provide some of their functionalities. It may be keepalived,
dnsmasq, haproxy or some other process.
Neutron agents are responsible for spawning and killing such processes when
necessary.  By default, to kill such processes, agents use a simple ``kill``
command, but in some cases, like for example when those additional services
are running inside containers, it may be not a good solution.
To address this problem, operators should use the ``AGENT`` config group option
``kill_scripts_path`` to configure a path to where ``kill scripts`` for such
processes live. By default, it is set to ``/etc/neutron/kill_scripts/``.
If option ``kill_scripts_path`` is changed in the config to the different
location, ``exec_dirs`` in ``/etc/rootwrap.conf`` should be changed accordingly.
If ``kill_scripts_path`` is set, every time neutron has to kill a process,
for example ``dnsmasq``, it will look in this directory for a file with the name
``<process_name>-kill``. So for ``dnsmasq`` process it will look for a
``dnsmasq-kill`` script. If such a file exists there, it will be called
instead of using the ``kill`` command.

Kill scripts are called with two parameters:

.. code-block::

    <process>-kill <sig> <pid>

where: ``<sig>`` is the signal, same as with the ``kill`` command, for example
``9`` or ``SIGKILL``; and ``<pid>`` is pid of the process to kill.

This external script should then handle killing of the given process as neutron
will not call the ``kill`` command for it anymore.
