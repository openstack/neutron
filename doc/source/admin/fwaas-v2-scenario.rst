Firewall-as-a-Service (FWaaS) v2 scenario
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   Firewall v2 has no support for OVN currently.

Enable FWaaS v2
---------------

#. Enable the FWaaS plug-in in the ``/etc/neutron/neutron.conf`` file:

   .. code-block:: ini

      service_plugins = firewall_v2

      [service_providers]
      # ...
      service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

      [fwaas]
      agent_version = v2
      driver = neutron_fwaas.services.firewall.service_drivers.agents.drivers.linux.iptables_fwaas_v2.IptablesFwaasDriver
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

#. Configure the ML2 plugin agent extension.

   Add the following statements to ``ml2_conf.ini``, this file is usually
   located at ``/etc/neutron/plugins/ml2/ml2_conf.ini``:

   .. code-block:: ini

      [agent]
      extensions = fwaas_v2

      [fwaas]
      firewall_l2_driver = noop

#. Create the required tables in the database:

   .. code-block:: console

      # neutron-db-manage --subproject neutron-fwaas upgrade head

#. Restart the ``neutron-l3-agent``, ``neutron-openvswitch-agent`` and
   ``neutron-server`` services to apply the settings.

Configure Firewall-as-a-Service v2
----------------------------------

Create the firewall rules and create a policy that contains them.
Then, create a firewall that applies the policy.

#. Create a firewall rule:

   .. code-block:: console

      $ openstack firewall group rule create --protocol {tcp,udp,icmp,any} \
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

      $ openstack firewall group policy create --firewall-rule \
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

#. Create a firewall group:

   .. code-block:: console

      $ openstack firewall group create --ingress-firewall-policy \
        "FIREWALL_POLICY_IDS_OR_NAMES" --egress-firewall-policy \
        "FIREWALL_POLICY_IDS_OR_NAMES" --port "PORT_IDS_OR_NAMES"

   Separate firewall policy IDs or names with spaces. The direction in which you
   specify the policies is important.

   .. note::

      The firewall remains in PENDING\_CREATE state until you create a
      Networking router and attach an interface to it.
