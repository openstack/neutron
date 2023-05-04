.. _config-dhcp-ha:

==========================
High-availability for DHCP
==========================

This section describes how to use the agent management (alias agent) and
scheduler (alias agent_scheduler) extensions for DHCP agents
scalability and HA.

.. note::

   Use the :command:`openstack extension list` command to check if these
   extensions are enabled. Check ``agent`` and ``agent_scheduler``
   are included in the output.

   .. code-block:: console

      $ openstack extension list --network -c Name -c Alias
      +-------------------------------------------------------------+---------------------------+
      | Name                                                        | Alias                     |
      +-------------------------------------------------------------+---------------------------+
      | Default Subnetpools                                         | default-subnetpools       |
      | Network IP Availability                                     | network-ip-availability   |
      | Network Availability Zone                                   | network_availability_zone |
      | Auto Allocated Topology Services                            | auto-allocated-topology   |
      | Neutron L3 Configurable external gateway mode               | ext-gw-mode               |
      | Port Binding                                                | binding                   |
      | Neutron Metering                                            | metering                  |
      | agent                                                       | agent                     |
      | Subnet Allocation                                           | subnet_allocation         |
      | L3 Agent Scheduler                                          | l3_agent_scheduler        |
      | Neutron external network                                    | external-net              |
      | Neutron Service Flavors                                     | flavors                   |
      | Network MTU                                                 | net-mtu                   |
      | Availability Zone                                           | availability_zone         |
      | Quota management support                                    | quotas                    |
      | HA Router extension                                         | l3-ha                     |
      | Provider Network                                            | provider                  |
      | Multi Provider Network                                      | multi-provider            |
      | Address scope                                               | address-scope             |
      | Neutron Extra Route                                         | extraroute                |
      | Subnet service types                                        | subnet-service-types      |
      | Resource timestamps                                         | standard-attr-timestamp   |
      | Neutron Service Type Management                             | service-type              |
      | Router Flavor Extension                                     | l3-flavors                |
      | Neutron Extra DHCP opts                                     | extra_dhcp_opt            |
      | Resource revision numbers                                   | standard-attr-revisions   |
      | Pagination support                                          | pagination                |
      | Sorting support                                             | sorting                   |
      | security-group                                              | security-group            |
      | DHCP Agent Scheduler                                        | dhcp_agent_scheduler      |
      | Router Availability Zone                                    | router_availability_zone  |
      | RBAC Policies                                               | rbac-policies             |
      | standard-attr-description                                   | standard-attr-description |
      | Neutron L3 Router                                           | router                    |
      | Allowed Address Pairs                                       | allowed-address-pairs     |
      | project_id field enabled                                    | project-id                |
      | Distributed Virtual Router                                  | dvr                       |
      +-------------------------------------------------------------+---------------------------+

Demo setup
~~~~~~~~~~

.. figure:: figures/demo_multiple_dhcp_agents.png

There will be three hosts in the setup.

.. list-table::
  :widths: 25 50
  :header-rows: 1

  * - Host
    - Description
  * - OpenStack controller host - controlnode
    - Runs the Networking, Identity, and Compute services that are required
      to deploy VMs. The node must have at least one network interface that
      is connected to the Management Network. Note that ``nova-network`` should
      not be running because it is replaced by Neutron.
  * - HostA
    - Runs ``nova-compute``, the Neutron L2 agent and DHCP agent
  * - HostB
    - Same as HostA

Configuration
~~~~~~~~~~~~~

**controlnode: neutron server**

#. Neutron configuration file ``/etc/neutron/neutron.conf``:

   .. code-block:: ini

      [DEFAULT]
      core_plugin = linuxbridge
      rabbit_host = controlnode
      allow_overlapping_ips = True
      host = controlnode
      agent_down_time = 5
      dhcp_agents_per_network = 1

   .. note::

      In the above configuration, we use ``dhcp_agents_per_network = 1``
      for this demonstration. In usual deployments, we suggest setting
      ``dhcp_agents_per_network`` to more than one to match the number of
      DHCP agents in your deployment.
      See :ref:`conf-dhcp-agents-per-network`.

#. Update the plug-in configuration file
   ``/etc/neutron/plugins/linuxbridge/linuxbridge_conf.ini``:

   .. code-block:: ini

      [vlans]
      tenant_network_type = vlan
      network_vlan_ranges = physnet1:1000:2999
      [database]
      connection = mysql+pymysql://root:root@127.0.0.1:3306/neutron_linux_bridge
      retry_interval = 2
      [linux_bridge]
      physical_interface_mappings = physnet1:eth0

**HostA and HostB: L2 agent**

#. Neutron configuration file ``/etc/neutron/neutron.conf``:

   .. code-block:: ini

      [DEFAULT]
      rabbit_host = controlnode
      rabbit_password = openstack
      # host = HostB on hostb
      host = HostA

#. Update the plug-in configuration file
   ``/etc/neutron/plugins/linuxbridge/linuxbridge_conf.ini``:

   .. code-block:: ini

      [vlans]
      tenant_network_type = vlan
      network_vlan_ranges = physnet1:1000:2999
      [database]
      connection = mysql://root:root@127.0.0.1:3306/neutron_linux_bridge
      retry_interval = 2
      [linux_bridge]
      physical_interface_mappings = physnet1:eth0

#. Update the nova configuration file ``/etc/nova/nova.conf``:

   .. code-block:: ini

      [DEFAULT]
      use_neutron=True
      firewall_driver=nova.virt.firewall.NoopFirewallDriver

      [neutron]
      admin_username=neutron
      admin_password=servicepassword
      admin_auth_url=http://controlnode:35357/v2.0/
      auth_strategy=keystone
      admin_tenant_name=servicetenant
      url=http://203.0.113.10:9696/

**HostA and HostB: DHCP agent**

- Update the DHCP configuration file ``/etc/neutron/dhcp_agent.ini``:

  .. code-block:: ini

     [DEFAULT]
     interface_driver = neutron.agent.linux.interface.BridgeInterfaceDriver

Prerequisites for demonstration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Admin role is required to use the agent management and scheduler extensions.
Ensure you run the following commands under a project with an admin role.

To experiment, you need VMs and a neutron network:

.. code-block:: console

   $ openstack server list
   +--------------------------------------+-----------+--------+----------------+--------+----------+
   | ID                                   | Name      | Status | Networks       | Image  | Flavor   |
   +--------------------------------------+-----------+--------+----------------+--------+----------+
   | c394fcd0-0baa-43ae-a793-201815c3e8ce | myserver1 | ACTIVE | net1=192.0.2.3 | cirros | m1.tiny  |
   | 2d604e05-9a6c-4ddb-9082-8a1fbdcc797d | myserver2 | ACTIVE | net1=192.0.2.4 | ubuntu | m1.small |
   | c7c0481c-3db8-4d7a-a948-60ce8211d585 | myserver3 | ACTIVE | net1=192.0.2.5 | centos | m1.small |
   +--------------------------------------+-----------+--------+----------------+--------+----------+

   $ openstack network list
   +--------------------------------------+------+--------------------------------------+
   | ID                                   | Name | Subnets                              |
   +--------------------------------------+------+--------------------------------------+
   | ad88e059-e7fa-4cf7-8857-6731a2a3a554 | net1 | 8086db87-3a7a-4cad-88c9-7bab9bc69258 |
   +--------------------------------------+------+--------------------------------------+

Managing agents in neutron deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. List all agents:

   .. code-block:: console

      $ openstack network agent list
      +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+
      | ID                                   | Agent Type         | Host  | Availability Zone | Alive | State | Binary                    |
      +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+
      | 22467163-01ea-4231-ba45-3bd316f425e6 | Linux bridge agent | HostA | None              | True  | UP    | neutron-linuxbridge-agent |
      | 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b | DHCP agent         | HostA | None              | True  | UP    | neutron-dhcp-agent        |
      | 3066d20c-9f8f-440c-ae7c-a40ffb4256b6 | Linux bridge agent | HostB | nova              | True  | UP    | neutron-linuxbridge-agent |
      | 55569f4e-6f31-41a6-be9d-526efce1f7fe | DHCP agent         | HostB | nova              | True  | UP    | neutron-dhcp-agent        |
      +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+

   Every agent that supports these extensions will register itself with the
   neutron server when it starts up.

   The output shows information for four agents. The ``alive`` field shows
   ``True`` if the agent reported its state within the period defined by the
   ``agent_down_time`` option in the ``neutron.conf`` file. Otherwise the
   ``alive`` is ``False``.

#. List DHCP agents that host a specified network:

   .. code-block:: console

      $ openstack network agent list --network net1
      +--------------------------------------+---------------+----------------+-------+
      | ID                                   | Host          | Admin State Up | Alive |
      +--------------------------------------+---------------+----------------+-------+
      | 22467163-01ea-4231-ba45-3bd316f425e6 | HostA         | UP             | True  |
      +--------------------------------------+---------------+----------------+-------+

#. List the networks hosted by a given DHCP agent:

   This command is to show which networks a given dhcp agent is managing.

   .. code-block:: console

      $ openstack network list --agent 22467163-01ea-4231-ba45-3bd316f425e6
      +--------------------------------+------------------------+---------------------------------+
      | ID                             | Name                   | Subnets                         |
      +--------------------------------+------------------------+---------------------------------+
      | ad88e059-e7fa-                 | net1                   | 8086db87-3a7a-4cad-             |
      | 4cf7-8857-6731a2a3a554         |                        | 88c9-7bab9bc69258               |
      +--------------------------------+------------------------+---------------------------------+

#. Show agent details.

   The :command:`openstack network agent show` command shows details for a
   specified agent:

   .. code-block:: console

      $ openstack network agent show 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b
      +---------------------+--------------------------------------------------+
      | Field               | Value                                            |
      +---------------------+--------------------------------------------------+
      | admin_state_up      | UP                                               |
      | agent_type          | DHCP agent                                       |
      | alive               | True                                             |
      | availability_zone   | nova                                             |
      | binary              | neutron-dhcp-agent                               |
      | configurations      | dhcp_driver='neutron.agent.linux.dhcp.Dnsmasq',  |
      |                     | dhcp_lease_duration='86400',                     |
      |                     | log_agent_heartbeats='False', networks='1',      |
      |                     | notifies_port_ready='True', ports='3',           |
      |                     | subnets='1'                                      |
      | created_at          | 2016-12-14 00:25:54                              |
      | description         | None                                             |
      | last_heartbeat_at   | 2016-12-14 06:53:24                              |
      | host                | HostA                                            |
      | id                  | 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b             |
      | started_at          | 2016-12-14 00:25:54                              |
      | topic               | dhcp_agent                                       |
      +---------------------+--------------------------------------------------+

   In this output, ``last_heartbeat_at`` is the time on the neutron
   server. You do not need to synchronize all agents to this time for this
   extension to run correctly. ``configurations`` describes the static
   configuration for the agent or run time data. This agent is a DHCP agent
   and it hosts one network, one subnet, and three ports.

   Different types of agents show different details. The following output
   shows information for a Linux bridge agent:

   .. code-block:: console

      $ openstack network agent show 22467163-01ea-4231-ba45-3bd316f425e6
      +---------------------+--------------------------------------+
      | Field               | Value                                |
      +---------------------+--------------------------------------+
      | admin_state_up      | UP                                   |
      | agent_type          | Linux bridge agent                   |
      | alive               | True                                 |
      | availability_zone   | nova                                 |
      | binary              | neutron-linuxbridge-agent            |
      | configurations      | {                                    |
      |                     |      "physnet1": "eth0",             |
      |                     |      "devices": "4"                  |
      |                     | }                                    |
      | created_at          | 2016-12-14 00:26:54                  |
      | description         | None                                 |
      | last_heartbeat_at   | 2016-12-14 06:53:24                  |
      | host                | HostA                                |
      | id                  | 22467163-01ea-4231-ba45-3bd316f425e6 |
      | started_at          | 2016-12-14T06:48:39.000000           |
      | topic               | N/A                                  |
      +---------------------+--------------------------------------+

   The output shows ``bridge-mapping`` and the number of virtual network
   devices on this L2 agent.

Managing assignment of networks to DHCP agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A single network can be assigned to more than one DHCP agents and
one DHCP agent can host more than one network.
You can add a network to a DHCP agent and remove one from it.

#. Default scheduling.

   When you create a network with one port, the network will be scheduled to
   an active DHCP agent. If many active DHCP agents are running, select one
   randomly. You can design more sophisticated scheduling algorithms in the
   same way as nova-schedule later on.

   .. code-block:: console

      $ openstack network create net2
      $ openstack subnet create --network net2 --subnet-range 198.51.100.0/24 subnet2
      $ openstack port create port2 --network net2
      $ openstack network agent list --network net2
      +--------------------------------------+---------------+----------------+-------+
      | ID                                   | Host          | Admin State Up | Alive |
      +--------------------------------------+---------------+----------------+-------+
      | 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b | HostA         | UP             | True  |
      +--------------------------------------+---------------+----------------+-------+

   It is allocated to DHCP agent on HostA. If you want to validate the
   behavior through the :command:`dnsmasq` command, you must create a subnet for
   the network because the DHCP agent starts the dnsmasq service only if
   there is a DHCP.

#. Assign a network to a given DHCP agent.

   To add another DHCP agent to host the network, run this command:

   .. code-block:: console

      $ openstack network agent add network --dhcp \
        55569f4e-6f31-41a6-be9d-526efce1f7fe net2
      $ openstack network agent list --network net2
      +--------------------------------------+-------+----------------+--------+
      | ID                                   | Host  | Admin State Up | Alive  |
      +--------------------------------------+-------+----------------+--------+
      | 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b | HostA | UP             | True   |
      | 55569f4e-6f31-41a6-be9d-526efce1f7fe | HostB | UP             | True   |
      +--------------------------------------+-------+----------------+--------+

   Both DHCP agents host the ``net2`` network.

#. Remove a network from a specified DHCP agent.

   This command is the sibling command for the previous one. Remove
   ``net2`` from the DHCP agent for HostA:

   .. code-block:: console

      $ openstack network agent remove network --dhcp \
        2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b net2
      $ openstack network agent list --network net2
      +--------------------------------------+-------+----------------+-------+
      | ID                                   | Host  | Admin State Up | Alive |
      +--------------------------------------+-------+----------------+-------+
      | 55569f4e-6f31-41a6-be9d-526efce1f7fe | HostB | UP             | True  |
      +--------------------------------------+-------+----------------+-------+

   You can see that only the DHCP agent for HostB is hosting the ``net2``
   network.

HA of DHCP agents
~~~~~~~~~~~~~~~~~

Boot a VM on ``net2``. Let both DHCP agents host ``net2``. Fail the agents
in turn to see if the VM can still get the desired IP.

#. Boot a VM on ``net2``:

   .. code-block:: console

      $ openstack network list
      +--------------------------------------+------+--------------------------------------+
      | ID                                   | Name | Subnets                              |
      +--------------------------------------+------+--------------------------------------+
      | ad88e059-e7fa-4cf7-8857-6731a2a3a554 | net1 | 8086db87-3a7a-4cad-88c9-7bab9bc69258 |
      | 9b96b14f-71b8-4918-90aa-c5d705606b1a | net2 | 6979b71a-0ae8-448c-aa87-65f68eedcaaa |
      +--------------------------------------+------+--------------------------------------+
      $ openstack server create --image tty  --flavor 1 myserver4 \
        --nic net-id=9b96b14f-71b8-4918-90aa-c5d705606b1a
      ...
      $ openstack server list
      +--------------------------------------+-----------+--------+-------------------+---------+----------+
      | ID                                   | Name      | Status | Networks          | Image   | Flavor   |
      +--------------------------------------+-----------+--------+-------------------+---------+----------+
      | c394fcd0-0baa-43ae-a793-201815c3e8ce | myserver1 | ACTIVE | net1=192.0.2.3    | cirros  | m1.tiny  |
      | 2d604e05-9a6c-4ddb-9082-8a1fbdcc797d | myserver2 | ACTIVE | net1=192.0.2.4    | ubuntu  | m1.small |
      | c7c0481c-3db8-4d7a-a948-60ce8211d585 | myserver3 | ACTIVE | net1=192.0.2.5    | centos  | m1.small |
      | f62f4731-5591-46b1-9d74-f0c901de567f | myserver4 | ACTIVE | net2=198.51.100.2 | cirros1 | m1.tiny  |
      +--------------------------------------+-----------+--------+-------------------+---------+----------+

#. Make sure both DHCP agents hosting ``net2``:

   Use the previous commands to assign the network to agents.

   .. code-block:: console

      $ openstack network agent list --network net2
      +--------------------------------------+-------+----------------+-------+
      | ID                                   | Host  | Admin State Up | Alive |
      +--------------------------------------+-------+----------------+-------+
      | 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b | HostA | UP             | True  |
      | 55569f4e-6f31-41a6-be9d-526efce1f7fe | HostB | UP             | True  |
      +--------------------------------------+-------+----------------+-------+

To test the HA of DHCP agent:

#. Log in to the ``myserver4`` VM, and run ``udhcpc``, ``dhclient`` or
   other DHCP client.

#. Stop the DHCP agent on HostA. Besides stopping the
   ``neutron-dhcp-agent`` binary, you must stop the ``dnsmasq`` processes.

#. Run a DHCP client in VM to see if it can get the wanted IP.

#. Stop the DHCP agent on HostB too.

#. Run ``udhcpc`` in the VM; it cannot get the wanted IP.

#. Start DHCP agent on HostB. The VM gets the wanted IP again.

No HA for metadata service on isolated networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All Neutron backends using the DHCP agent can also provide `metadata service
<https://docs.openstack.org/nova/latest/user/metadata.html>`_ in isolated
networks (i.e. networks without a router). In this case the DHCP agent manages
the metadata service (see config option `enable_isolated_metadata
<https://docs.openstack.org/neutron/latest/configuration/dhcp-agent.html#DEFAULT.enable_isolated_metadata>`_).

Note however that the metadata service is only redundant for IPv4, and not
IPv6, even when the DHCP service is configured to be highly available
(config option `dhcp_agents_per_network
<https://docs.openstack.org/neutron/latest/configuration/neutron.html#DEFAULT.dhcp_agents_per_network>`_
> 1). This is because the DHCP agent will insert a route to the well known
metadata IPv4 address (`169.254.169.254`) via its own IP address, so it will
be reachable as long as the DHCP service is available at that IP address.
This also means that recovery after a failure is tied to the renewal of the
DHCP lease, since that route will only change if the DHCP server for a VM
changes.

With IPv6, the well known metadata IPv6 address (`fe80::a9fe:a9fe`) is used,
but directly configured in the DHCP agent network namespace.
Due to the enforcement of duplicate address detection (DAD), this address
can only be configured in at most one DHCP network namespaces at any time.
See `RFC 4862 <https://www.rfc-editor.org/rfc/rfc4862#section-5.4>`_ for
details on the DAD process.

For this reason, even when you have multiple DHCP agents, an arbitrary one
(where the metadata IPv6 address is not in `dadfailed` state) will serve all
metadata requests over IPv6. When that metadata service instance becomes
unreachable there is no failover and the service will become unreachable.

Disabling and removing an agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An administrator might want to disable an agent if a system hardware or
software upgrade is planned. Some agents that support scheduling also
support disabling and enabling agents, such as L3 and DHCP agents. After
the agent is disabled, the scheduler does not schedule new resources to
the agent.

After the agent is disabled, you can safely remove the agent.
Even after disabling the agent, resources on the agent are kept assigned.
Ensure you remove the resources on the agent before you delete the agent.

Disable the DHCP agent on HostA before you stop it:

.. code-block:: console

   $ openstack network agent set 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b --disable
   $ openstack network agent list
   +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+
   | ID                                   | Agent Type         | Host  | Availability Zone | Alive | State | Binary                    |
   +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+
   | 22467163-01ea-4231-ba45-3bd316f425e6 | Linux bridge agent | HostA | None              | True  | UP    | neutron-linuxbridge-agent |
   | 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b | DHCP agent         | HostA | None              | True  | DOWN  | neutron-dhcp-agent        |
   | 3066d20c-9f8f-440c-ae7c-a40ffb4256b6 | Linux bridge agent | HostB | nova              | True  | UP    | neutron-linuxbridge-agent |
   | 55569f4e-6f31-41a6-be9d-526efce1f7fe | DHCP agent         | HostB | nova              | True  | UP    | neutron-dhcp-agent        |
   +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+

After you stop the DHCP agent on HostA, you can delete it by the following
command:

.. code-block:: console

   $ openstack network agent delete 2444c54d-0d28-460c-ab0f-cd1e6b5d3c7b
   $ openstack network agent list
   +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+
   | ID                                   | Agent Type         | Host  | Availability Zone | Alive | State | Binary                    |
   +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+
   | 22467163-01ea-4231-ba45-3bd316f425e6 | Linux bridge agent | HostA | None              | True  | UP    | neutron-linuxbridge-agent |
   | 3066d20c-9f8f-440c-ae7c-a40ffb4256b6 | Linux bridge agent | HostB | nova              | True  | UP    | neutron-linuxbridge-agent |
   | 55569f4e-6f31-41a6-be9d-526efce1f7fe | DHCP agent         | HostB | nova              | True  | UP    | neutron-dhcp-agent        |
   +--------------------------------------+--------------------+-------+-------------------+-------+-------+---------------------------+

After deletion, if you restart the DHCP agent, it appears on the agent
list again.

.. _conf-dhcp-agents-per-network:

Enabling DHCP high availability by default
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can control the default number of DHCP agents assigned to a network
by setting the following configuration option
in the file ``/etc/neutron/neutron.conf``.

.. code-block:: ini

   dhcp_agents_per_network = 3
