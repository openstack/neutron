========================
Configure neutron agents
========================

Plug-ins typically have requirements for particular software that must
be run on each node that handles data packets. This includes any node
that runs nova-compute and nodes that run dedicated OpenStack Networking
service agents such as ``neutron-dhcp-agent``, ``neutron-l3-agent`` or
``neutron-metering-agent``.

A data-forwarding node typically has a network interface with an IP
address on the management network and another interface on the data
network.

This section shows you how to install and configure a subset of the
available plug-ins, which might include the installation of switching
software (for example, ``Open vSwitch``) and as agents used to communicate
with the ``neutron-server`` process running elsewhere in the data center.

Configure data-forwarding nodes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Node set up: NSX plug-in
------------------------

If you use the NSX plug-in, you must also install Open vSwitch on each
data-forwarding node. However, you do not need to install an additional
agent on each node.

.. warning::

   It is critical that you run an Open vSwitch version that is
   compatible with the current version of the NSX Controller software.
   Do not use the Open vSwitch version that is installed by default on
   Ubuntu. Instead, use the Open vSwitch version that is provided on
   the VMware support portal for your NSX Controller version.

**To set up each node for the NSX plug-in**

#. Ensure that each data-forwarding node has an IP address on the
   management network, and an IP address on the data network that is used
   for tunneling data traffic. For full details on configuring your
   forwarding node, see the `NSX Administration Guide
   <https://www.vmware.com/support/pubs/>`__.

#. Use the NSX Administrator Guide to add the node as a Hypervisor
   by using the NSX Manager GUI. Even if your forwarding node has no
   VMs and is only used for services agents like ``neutron-dhcp-agent``
   , it should still be added to NSX as a
   Hypervisor.

#. After following the NSX Administrator Guide, use the page for this
   Hypervisor in the NSX Manager GUI to confirm that the node is properly
   connected to the NSX Controller Cluster and that the NSX Controller
   Cluster can see the ``br-int`` integration bridge.

Configure DHCP agent
~~~~~~~~~~~~~~~~~~~~

The DHCP service agent is compatible with all existing plug-ins and is
required for all deployments where VMs should automatically receive IP
addresses through DHCP.

**To install and configure the DHCP agent**

#. You must configure the host running the neutron-dhcp-agent as a data
   forwarding node according to the requirements for your plug-in.

#. Install the DHCP agent:

   .. code-block:: console

      # apt-get install neutron-dhcp-agent

#. Update any options in the ``/etc/neutron/dhcp_agent.ini`` file
   that depend on the plug-in in use. See the sub-sections.

   .. important::

      If you reboot a node that runs the DHCP agent, you must run the
      :command:`neutron-ovs-cleanup` command before the ``neutron-dhcp-agent``
      service starts.

      On Red Hat, SUSE, and Ubuntu based systems, the
      ``neutron-ovs-cleanup`` service runs the :command:`neutron-ovs-cleanup`
      command automatically. However, on Debian-based systems, you
      must manually run this command or write your own system script
      that runs on boot before the ``neutron-dhcp-agent`` service starts.

Networking dhcp-agent can use
`dnsmasq <http://www.thekelleys.org.uk/dnsmasq/doc.html>`__ driver which
supports stateful and stateless DHCPv6 for subnets created with
``--ipv6_address_mode`` set to ``dhcpv6-stateful`` or
``dhcpv6-stateless``.

For example:

.. code-block:: console

   $ openstack subnet create --ip-version 6 --ipv6-ra-mode dhcpv6-stateful \
     --ipv6-address-mode dhcpv6-stateful --network NETWORK --subnet-range \
     CIDR SUBNET_NAME

.. code-block:: console

   $ openstack subnet create --ip-version 6 --ipv6-ra-mode dhcpv6-stateless \
     --ipv6-address-mode dhcpv6-stateless --network NETWORK --subnet-range \
     CIDR SUBNET_NAME

If no dnsmasq process for subnet's network is launched, Networking will
launch a new one on subnet's dhcp port in ``qdhcp-XXX`` namespace. If
previous dnsmasq process is already launched, restart dnsmasq with a new
configuration.

Networking will update dnsmasq process and restart it when subnet gets
updated.

.. note::

   For dhcp-agent to operate in IPv6 mode use at least dnsmasq v2.63.

After a certain, configured timeframe, networks uncouple from DHCP
agents when the agents are no longer in use. You can configure the DHCP
agent to automatically detach from a network when the agent is out of
service, or no longer needed.

This feature applies to all plug-ins that support DHCP scaling. For more
information, see the `DHCP agent configuration
options <https://docs.openstack.org/ocata/config-reference/networking/networking_options_reference.html#dhcp-agent>`__
listed in the OpenStack Configuration Reference.

DHCP agent setup: OVS plug-in
-----------------------------

These DHCP agent options are required in the
``/etc/neutron/dhcp_agent.ini`` file for the OVS plug-in:

.. code-block:: bash

   [DEFAULT]
   enable_isolated_metadata = True
   interface_driver = openvswitch

DHCP agent setup: NSX plug-in
-----------------------------

These DHCP agent options are required in the
``/etc/neutron/dhcp_agent.ini`` file for the NSX plug-in:

.. code-block:: bash

   [DEFAULT]
   enable_metadata_network = True
   enable_isolated_metadata = True
   interface_driver = openvswitch

DHCP agent setup: Linux-bridge plug-in
--------------------------------------

These DHCP agent options are required in the
``/etc/neutron/dhcp_agent.ini`` file for the Linux-bridge plug-in:

.. code-block:: bash

   [DEFAULT]
   enabled_isolated_metadata = True
   interface_driver = linuxbridge

Configure L3 agent
~~~~~~~~~~~~~~~~~~

The OpenStack Networking service has a widely used API extension to
allow administrators and projects to create routers to interconnect L2
networks, and floating IPs to make ports on private networks publicly
accessible.

Many plug-ins rely on the L3 service agent to implement the L3
functionality. However, the following plug-ins already have built-in L3
capabilities:

-  Big Switch/Floodlight plug-in, which supports both the open source
   `Floodlight <http://www.projectfloodlight.org/floodlight/>`__
   controller and the proprietary Big Switch controller.

   .. note::

      Only the proprietary BigSwitch controller implements L3
      functionality. When using Floodlight as your OpenFlow controller,
      L3 functionality is not available.

-  IBM SDN-VE plug-in

-  MidoNet plug-in

-  NSX plug-in

-  PLUMgrid plug-in

.. warning::

   Do not configure or use ``neutron-l3-agent`` if you use one of these
   plug-ins.

**To install the L3 agent for all other plug-ins**

#. Install the ``neutron-l3-agent`` binary on the network node:

   .. code-block:: console

      # apt-get install neutron-l3-agent

#. To uplink the node that runs ``neutron-l3-agent`` to the external network,
   create a bridge named ``br-ex`` and attach the NIC for the external
   network to this bridge.

   For example, with Open vSwitch and NIC eth1 connected to the external
   network, run:

   .. code-block:: console

      # ovs-vsctl add-br br-ex
      # ovs-vsctl add-port br-ex eth1

   When the ``br-ex`` port is added to the ``eth1`` interface, external
   communication is interrupted. To avoid this, edit the
   ``/etc/network/interfaces`` file to contain the following information:

   .. code-block:: shell

      ## External bridge
      auto br-ex
      iface br-ex inet static
      address 192.27.117.101
      netmask 255.255.240.0
      gateway 192.27.127.254
      dns-nameservers 8.8.8.8

      ## External network interface
      auto eth1
      iface eth1 inet manual
      up ifconfig $IFACE 0.0.0.0 up
      up ip link set $IFACE promisc on
      down ip link set $IFACE promisc off
      down ifconfig $IFACE down

   .. note::

      The external bridge configuration address is the external IP address.
      This address and gateway should be configured in
      ``/etc/network/interfaces``.

   After editing the configuration, restart ``br-ex``:

   .. code-block:: console

      # ifdown br-ex && ifup br-ex

   Do not manually configure an IP address on the NIC connected to the
   external network for the node running ``neutron-l3-agent``. Rather, you
   must have a range of IP addresses from the external network that can be
   used by OpenStack Networking for routers that uplink to the external
   network. This range must be large enough to have an IP address for each
   router in the deployment, as well as each floating IP.

#. The ``neutron-l3-agent`` uses the Linux IP stack and iptables to perform L3
   forwarding and NAT. In order to support multiple routers with
   potentially overlapping IP addresses, ``neutron-l3-agent`` defaults to
   using Linux network namespaces to provide isolated forwarding contexts.
   As a result, the IP addresses of routers are not visible simply by running
   the :command:`ip addr list` or :command:`ifconfig` command on the node.
   Similarly, you cannot directly :command:`ping` fixed IPs.

   To do either of these things, you must run the command within a
   particular network namespace for the router. The namespace has the name
   ``qrouter-ROUTER_UUID``. These example commands run in the router
   namespace with UUID 47af3868-0fa8-4447-85f6-1304de32153b:

   .. code-block:: console

      # ip netns exec qrouter-47af3868-0fa8-4447-85f6-1304de32153b ip addr list

   .. code-block:: console

      # ip netns exec qrouter-47af3868-0fa8-4447-85f6-1304de32153b ping FIXED_IP

   .. important::

      If you reboot a node that runs the L3 agent, you must run the
      :command:`neutron-ovs-cleanup` command before the ``neutron-l3-agent``
      service starts.

      On Red Hat, SUSE and Ubuntu based systems, the neutron-ovs-cleanup
      service runs the :command:`neutron-ovs-cleanup` command
      automatically. However, on Debian-based systems, you must manually
      run this command or write your own system script that runs on boot
      before the neutron-l3-agent service starts.

**How routers are assigned to L3 agents**
By default, a router is assigned to the L3 agent with the least number
of routers (LeastRoutersScheduler). This can be changed by altering the
``router_scheduler_driver`` setting in the configuration file.

Configure metering agent
~~~~~~~~~~~~~~~~~~~~~~~~

The Neutron Metering agent resides beside neutron-l3-agent.

**To install the metering agent and configure the node**

#. Install the agent by running:

   .. code-block:: console

      # apt-get install neutron-metering-agent

#. If you use one of the following plug-ins, you need to configure the
   metering agent with these lines as well:

   -  An OVS-based plug-in such as OVS, NSX, NEC, BigSwitch/Floodlight:

      .. code-block:: ini

         interface_driver = openvswitch

   -  A plug-in that uses LinuxBridge:

      .. code-block:: ini

         interface_driver = linuxbridge

#. To use the reference implementation, you must set:

   .. code-block:: ini

      driver = iptables

#. Set the ``service_plugins`` option in the ``/etc/neutron/neutron.conf``
   file on the host that runs ``neutron-server``:

   .. code-block:: ini

      service_plugins = metering

   If this option is already defined, add ``metering`` to the list, using a
   comma as separator. For example:

   .. code-block:: ini

      service_plugins = router,metering

Configure Hyper-V L2 agent
~~~~~~~~~~~~~~~~~~~~~~~~~~

Before you install the OpenStack Networking Hyper-V L2 agent on a
Hyper-V compute node, ensure the compute node has been configured
correctly using these
`instructions <https://docs.openstack.org/ocata/config-reference/compute/hypervisor-hyper-v.html>`__.

**To install the OpenStack Networking Hyper-V agent and configure the node**

#. Download the OpenStack Networking code from the repository:

   .. code-block:: console

      > cd C:\OpenStack\
      > git clone https://opendev.org/openstack/neutron

#. Install the OpenStack Networking Hyper-V Agent:

   .. code-block:: console

      > cd C:\OpenStack\neutron\
      > python setup.py install

#. Copy the ``policy.json`` file:

   .. code-block:: console

      > xcopy C:\OpenStack\neutron\etc\policy.json C:\etc\

#. Create the ``C:\etc\neutron-hyperv-agent.conf`` file and add the proper
   configuration options and the `Hyper-V related
   options <https://docs.openstack.org/ocata/config-reference/networking/networking_options_reference.html#cloudbase-hyper-v-agent-configuration-options>`__. Here is a sample config file:

   .. code-block:: ini

      [DEFAULT]
      control_exchange = neutron
      policy_file = C:\etc\policy.json
      rpc_backend = neutron.openstack.common.rpc.impl_kombu
      rabbit_host = IP_ADDRESS
      rabbit_port = 5672
      rabbit_userid = guest
      rabbit_password = <password>
      logdir = C:\OpenStack\Log
      logfile = neutron-hyperv-agent.log

      [AGENT]
      polling_interval = 2
      physical_network_vswitch_mappings = *:YOUR_BRIDGE_NAME
      enable_metrics_collection = true

      [SECURITYGROUP]
      firewall_driver = hyperv.neutron.security_groups_driver.HyperVSecurityGroupsDriver
      enable_security_group = true

#. Start the OpenStack Networking Hyper-V agent:

   .. code-block:: console

      > C:\Python27\Scripts\neutron-hyperv-agent.exe --config-file
      C:\etc\neutron-hyperv-agent.conf

Basic operations on agents
~~~~~~~~~~~~~~~~~~~~~~~~~~

This table shows examples of Networking commands that enable you to
complete basic operations on agents.

.. list-table::
   :widths: 50 50
   :header-rows: 1

   * - Operation
     - Command
   * - List all available agents.
     - ``$ openstack network agent list``
   * - Show information of a given agent.
     - ``$ openstack network agent show AGENT_ID``
   * - Update the admin status and description for a specified agent. The
       command can be used to enable and disable agents by using
       ``--admin-state-up`` parameter set to ``False`` or ``True``.
     - ``$ neutron agent-update --admin-state-up False AGENT_ID``
   * - Delete a given agent. Consider disabling the agent before deletion.
     - ``$ openstack network agent delete AGENT_ID``

**Basic operations on Networking agents**

See the `OpenStack Command-Line Interface
Reference <https://docs.openstack.org/cli-reference/neutron.html>`__
for more information on Networking commands.
