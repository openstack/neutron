Networking Option 1: Provider networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure the Networking components on a *compute* node.

Configure the Open vSwitch agent
--------------------------------

The Open vSwitch agent builds layer-2 (bridging and switching) virtual
networking infrastructure for instances and handles security groups.

* Edit the ``/etc/neutron/plugins/ml2/openvswitch_agent.ini`` file and
  complete the following actions:

  * In the ``[ovs]`` section, map the provider virtual network to the
    provider physical bridge:

    .. path /etc/neutron/plugins/ml2/openvswitch_agent.ini
    .. code-block:: ini

       [ovs]
       bridge_mappings = provider:PROVIDER_BRIDGE_NAME

    .. end

    Replace ``PROVIDER_BRIDGE_NAME`` with the name of the bridge connected to
    the underlying provider physical network.
    See :doc:`environment-networking-ubuntu` and
    :doc:`../admin/deploy-ovs-provider` for more information.

  * Ensure ``PROVIDER_BRIDGE_NAME`` external bridge is created and
    ``PROVIDER_INTERFACE_NAME`` is added to that bridge

    .. code-block:: bash

       # ovs-vsctl add-br $PROVIDER_BRIDGE_NAME
       # ovs-vsctl add-port $PROVIDER_BRIDGE_NAME $PROVIDER_INTERFACE_NAME

    .. end

  * In the ``[securitygroup]`` section, enable security groups and
    configure the Open vSwitch native or the hybrid iptables firewall driver:

    .. path /etc/neutron/plugins/ml2/openvswitch_agent.ini
    .. code-block:: ini

       [securitygroup]
       # ...
       enable_security_group = true
       firewall_driver = openvswitch
       #firewall_driver = iptables_hybrid

    .. end

  * In the case of using the hybrid iptables firewall driver, ensure your
    Linux operating system kernel supports network bridge filters by verifying
    all the following ``sysctl`` values are set to ``1``:

    .. code-block:: ini

        net.bridge.bridge-nf-call-iptables
        net.bridge.bridge-nf-call-ip6tables

    .. end

    To enable networking bridge support, typically the ``br_netfilter`` kernel
    module needs to be loaded. Check your operating system's documentation for
    additional details on enabling this module.

Return to *Networking compute node configuration*
