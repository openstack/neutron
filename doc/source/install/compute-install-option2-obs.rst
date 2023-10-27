Networking Option 2: Self-service networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure the Networking components on a *compute* node.

Configure the Open vSwitch agent
--------------------------------

The Open vSwitch agent builds layer-2 (bridging and switching) virtual
networking infrastructure for instances and handles security groups.

* Edit the ``/etc/neutron/plugins/ml2/openvswitch_agent.ini`` file and
  complete the following actions:

  * In the ``[ovs]`` section, map the provider virtual network to the
    provider physical bridge and configure the IP address of
    the physical network interface that handles overlay networks:

    .. path /etc/neutron/plugins/ml2/openvswitch_agent.ini
    .. code-block:: ini

       [ovs]
       bridge_mappings = provider:PROVIDER_BRIDGE_NAME
       local_ip = OVERLAY_INTERFACE_IP_ADDRESS

    .. end

    Replace ``PROVIDER_BRIDGE_NAME`` with the name of the bridge connected to
    the underlying provider physical network.
    See :doc:`environment-networking-obs`
    and :doc:`../admin/deploy-ovs-provider` for more information.

    Also replace ``OVERLAY_INTERFACE_IP_ADDRESS`` with the IP address of the
    underlying physical network interface that handles overlay networks. The
    example architecture uses the management interface to tunnel traffic to
    the other nodes. Therefore, replace ``OVERLAY_INTERFACE_IP_ADDRESS`` with
    the management IP address of the compute node. See
    :doc:`environment-networking-obs` for more information.

  * Ensure ``PROVIDER_BRIDGE_NAME`` external bridge is created and
    ``PROVIDER_INTERFACE_NAME`` is added to that bridge

    .. code-block:: bash

       # ovs-vsctl add-br $PROVIDER_BRIDGE_NAME
       # ovs-vsctl add-port $PROVIDER_BRIDGE_NAME $PROVIDER_INTERFACE_NAME

    .. end

  * In the ``[agent]`` section, enable VXLAN overlay networks and enable
    layer-2 population:

    .. path /etc/neutron/plugins/ml2/openvswitch_agent.ini
    .. code-block:: ini

       [agent]
       tunnel_types = vxlan
       l2_population = true

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

Return to *Networking compute node configuration*.
