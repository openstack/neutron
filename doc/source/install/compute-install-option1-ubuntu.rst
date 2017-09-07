Networking Option 1: Provider networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure the Networking components on a *compute* node.

Configure the Linux bridge agent
--------------------------------

The Linux bridge agent builds layer-2 (bridging and switching) virtual
networking infrastructure for instances and handles security groups.

* Edit the ``/etc/neutron/plugins/ml2/linuxbridge_agent.ini`` file and
  complete the following actions:

  * In the ``[linux_bridge]`` section, map the provider virtual network to the
    provider physical network interface:

    .. path /etc/neutron/plugins/ml2/linuxbridge_agent.ini
    .. code-block:: ini

       [linux_bridge]
       physical_interface_mappings = provider:PROVIDER_INTERFACE_NAME

    .. end

    Replace ``PROVIDER_INTERFACE_NAME`` with the name of the underlying
    provider physical network interface. See :doc:`environment-networking-ubuntu`
    for more information.

  * In the ``[vxlan]`` section, disable VXLAN overlay networks:

    .. path /etc/neutron/plugins/ml2/linuxbridge_agent.ini
    .. code-block:: ini

       [vxlan]
       enable_vxlan = false

    .. end

  * In the ``[securitygroup]`` section, enable security groups and
    configure the Linux bridge iptables firewall driver:

    .. path /etc/neutron/plugins/ml2/linuxbridge_agent.ini
    .. code-block:: ini

       [securitygroup]
       # ...
       enable_security_group = true
       firewall_driver = neutron.agent.linux.iptables_firewall.IptablesFirewallDriver

    .. end

  * Ensure your Linux operating system kernel supports network bridge filters
    by verifying all the following ``sysctl`` values are set to ``1``:

    .. code-block:: ini

        net.bridge.bridge-nf-call-iptables
        net.bridge.bridge-nf-call-ip6tables

    .. end

    To enable networking bridge support, typically the ``br_netfilter`` kernel
    module needs to be loaded. Check your operating system's documentation for
    additional details on enabling this module.

Return to *Networking compute node configuration*
