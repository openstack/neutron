Firewall-as-a-Service (FWaaS) v2 scenario
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enable FWaaS v2
---------------

#. Enable the FWaaS plug-in in the ``/etc/neutron/neutron.conf`` file:

   .. code-block:: ini

      service_plugins = firewall_v2

      [service_providers]
      # ...
      service_provider = FIREWALL:Iptables:neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver:default

      [fwaas]
      agent_version = v2
      driver = neutron_fwaas.services.firewall.drivers.linux.iptables_fwaas_v2.IptablesFwaasDriver
      enabled = True

   .. note::

      On Ubuntu and Centos, modify the ``[fwaas]`` section in the
      ``/etc/neutron/fwaas_driver.ini`` file instead of
      ``/etc/neutron/neutron.conf``.

#. Configure the FWaaS plugin for the L3 agent.

   In the ``AGENT`` section of ``l3_agent.ini``, make sure the FWaaS v2
   extension is loaded:

   .. code-block:: ini

      [AGENT]
      extensions = fwaas_v2

#. Create the required tables in the database:

   .. code-block:: console

      # neutron-db-manage --subproject neutron-fwaas upgrade head

#. Restart the ``neutron-l3-agent`` and ``neutron-server`` services
   to apply the settings.

   .. note::

      Firewall v2 is not supported by horizon yet.

Configure Firewall-as-a-Service v2
----------------------------------

Create the firewall rules and create a policy that contains them.
Then, create a firewall that applies the policy.

#. Create a firewall rule:

   .. code-block:: console

      $ neutron firewall-rule-create --protocol {tcp,udp,icmp,any} \
        --source-ip-address SOURCE_IP_ADDRESS \
        --destination-ip-address DESTINATION_IP_ADDRESS \
        --source-port SOURCE_PORT_RANGE --destination-port DEST_PORT_RANGE \
        --action {allow,deny,reject}

   The Networking client requires a protocol value.  If the rule is protocol
   agnostic, you can use the ``any`` value.

   .. note::

      When the source or destination IP address are not of the same IP
      version (for example, IPv6), the command returns an error.

#. Create a firewall policy:

   .. code-block:: console

      $ neutron firewall-policy-create --firewall-rules \
        "FIREWALL_RULE_IDS_OR_NAMES" myfirewallpolicy

   Separate firewall rule IDs or names with spaces. The order in which you
   specify the rules is important.

   You can create a firewall policy without any rules and add rules later,
   as follows:

   * To add multiple rules, use the update operation.

   * To add a single rule, use the insert-rule operation.

   For more details, see `Networking command-line client
   <https://docs.openstack.org/cli-reference/neutron.html>`_
   in the OpenStack Command-Line Interface Reference.

   .. note::

      FWaaS always adds a default ``deny all`` rule at the lowest precedence
      of each policy. Consequently, a firewall policy with no rules blocks
      all traffic by default.

#. Create a firewall:

   .. code-block:: console

      $ neutron firewall-create FIREWALL_POLICY_UUID

   .. note::

      The firewall remains in PENDING\_CREATE state until you create a
      Networking router and attach an interface to it.
