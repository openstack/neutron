Networking Option 2: Self-service networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install and configure the Networking components on the *controller* node.

Install the components
----------------------


.. code-block:: console

   # apt install neutron-server neutron-plugin-ml2 \
     neutron-linuxbridge-agent neutron-l3-agent neutron-dhcp-agent \
     neutron-metadata-agent

.. end





Configure the server component
------------------------------

* Edit the ``/etc/neutron/neutron.conf`` file and complete the following
  actions:

  * In the ``[database]`` section, configure database access:

    .. path /etc/neutron/neutron.conf
    .. code-block:: ini

       [database]
       # ...
       connection = mysql+pymysql://neutron:NEUTRON_DBPASS@controller/neutron

    .. end

    Replace ``NEUTRON_DBPASS`` with the password you chose for the
    database.

    .. note::

       Comment out or remove any other ``connection`` options in the
       ``[database]`` section.

  * In the ``[DEFAULT]`` section, enable the Modular Layer 2 (ML2)
    plug-in, router service, and overlapping IP addresses:

    .. path /etc/neutron/neutron.conf
    .. code-block:: ini

       [DEFAULT]
       # ...
       core_plugin = ml2
       service_plugins = router

    .. end

  * In the ``[DEFAULT]`` section, configure ``RabbitMQ``
    message queue access:

    .. path /etc/neutron/neutron.conf
    .. code-block:: ini

       [DEFAULT]
       # ...
       transport_url = rabbit://openstack:RABBIT_PASS@controller

    .. end

    Replace ``RABBIT_PASS`` with the password you chose for the
    ``openstack`` account in RabbitMQ.

  * In the ``[DEFAULT]`` and ``[keystone_authtoken]`` sections, configure
    Identity service access:

    .. path /etc/neutron/neutron.conf
    .. code-block:: ini

       [DEFAULT]
       # ...
       auth_strategy = keystone

       [keystone_authtoken]
       # ...
       www_authenticate_uri = http://controller:5000
       auth_url = http://controller:5000
       memcached_servers = controller:11211
       auth_type = password
       project_domain_name = default
       user_domain_name = default
       project_name = service
       username = neutron
       password = NEUTRON_PASS

    .. end

    Replace ``NEUTRON_PASS`` with the password you chose for the ``neutron``
    user in the Identity service.

    .. note::

       Comment out or remove any other options in the
       ``[keystone_authtoken]`` section.

  * In the ``[DEFAULT]`` and ``[nova]`` sections, configure Networking to
    notify Compute of network topology changes:

    .. path /etc/neutron/neutron.conf
    .. code-block:: ini

       [DEFAULT]
       # ...
       notify_nova_on_port_status_changes = true
       notify_nova_on_port_data_changes = true

       [nova]
       # ...
       auth_url = http://controller:5000
       auth_type = password
       project_domain_name = default
       user_domain_name = default
       region_name = RegionOne
       project_name = service
       username = nova
       password = NOVA_PASS

    .. end

    Replace ``NOVA_PASS`` with the password you chose for the ``nova``
    user in the Identity service.


* In the ``[oslo_concurrency]`` section, configure the lock path:

  .. path /etc/neutron/neutron.conf
  .. code-block:: ini

     [oslo_concurrency]
     # ...
     lock_path = /var/lib/neutron/tmp

  .. end

Configure the Modular Layer 2 (ML2) plug-in
-------------------------------------------

The ML2 plug-in uses the Linux bridge mechanism to build layer-2 (bridging
and switching) virtual networking infrastructure for instances.

* Edit the ``/etc/neutron/plugins/ml2/ml2_conf.ini`` file and complete the
  following actions:

  * In the ``[ml2]`` section, enable flat, VLAN, and VXLAN networks:

    .. path /etc/neutron/plugins/ml2/ml2_conf.ini
    .. code-block:: ini

       [ml2]
       # ...
       type_drivers = flat,vlan,vxlan

    .. end

  * In the ``[ml2]`` section, enable VXLAN self-service networks:

    .. path /etc/neutron/plugins/ml2/ml2_conf.ini
    .. code-block:: ini

       [ml2]
       # ...
       tenant_network_types = vxlan

    .. end

  * In the ``[ml2]`` section, enable the Linux bridge and layer-2 population
    mechanisms:

    .. path /etc/neutron/plugins/ml2/ml2_conf.ini
    .. code-block:: ini

       [ml2]
       # ...
       mechanism_drivers = linuxbridge,l2population

    .. end

    .. warning::

       After you configure the ML2 plug-in, removing values in the
       ``type_drivers`` option can lead to database inconsistency.

    .. note::

       The Linux bridge agent only supports VXLAN overlay networks.

  * In the ``[ml2]`` section, enable the port security extension driver:

    .. path /etc/neutron/plugins/ml2/ml2_conf.ini
    .. code-block:: ini

       [ml2]
       # ...
       extension_drivers = port_security

    .. end

  * In the ``[ml2_type_flat]`` section, configure the provider virtual
    network as a flat network:

    .. path /etc/neutron/plugins/ml2/ml2_conf.ini
    .. code-block:: ini

       [ml2_type_flat]
       # ...
       flat_networks = provider

    .. end

  * In the ``[ml2_type_vxlan]`` section, configure the VXLAN network identifier
    range for self-service networks:

    .. path /etc/neutron/plugins/ml2/ml2_conf.ini
    .. code-block:: ini

       [ml2_type_vxlan]
       # ...
       vni_ranges = 1:1000

    .. end

  * In the ``[securitygroup]`` section, enable ipset to increase
    efficiency of security group rules:

    .. path /etc/neutron/plugins/ml2/ml2_conf.ini
    .. code-block:: ini

       [securitygroup]
       # ...
       enable_ipset = true

    .. end

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

  * In the ``[vxlan]`` section, enable VXLAN overlay networks, configure the
    IP address of the physical network interface that handles overlay
    networks, and enable layer-2 population:

    .. path /etc/neutron/plugins/ml2/linuxbridge_agent.ini
    .. code-block:: ini

       [vxlan]
       enable_vxlan = true
       local_ip = OVERLAY_INTERFACE_IP_ADDRESS
       l2_population = true

    .. end

    Replace ``OVERLAY_INTERFACE_IP_ADDRESS`` with the IP address of the
    underlying physical network interface that handles overlay networks. The
    example architecture uses the management interface to tunnel traffic to
    the other nodes. Therefore, replace ``OVERLAY_INTERFACE_IP_ADDRESS`` with
    the management IP address of the controller node. See
    :doc:`environment-networking-ubuntu` for more information.

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

Configure the layer-3 agent
---------------------------

The Layer-3 (L3) agent provides routing and NAT services for
self-service virtual networks.

* Edit the ``/etc/neutron/l3_agent.ini`` file and complete the following
  actions:

  * In the ``[DEFAULT]`` section, configure the Linux bridge interface driver:

    .. path /etc/neutron/l3_agent.ini
    .. code-block:: ini

       [DEFAULT]
       # ...
       interface_driver = linuxbridge

    .. end

Configure the DHCP agent
------------------------

The DHCP agent provides DHCP services for virtual networks.

* Edit the ``/etc/neutron/dhcp_agent.ini`` file and complete the following
  actions:

  * In the ``[DEFAULT]`` section, configure the Linux bridge interface driver,
    Dnsmasq DHCP driver, and enable isolated metadata so instances on provider
    networks can access metadata over the network:

    .. path /etc/neutron/dhcp_agent.ini
    .. code-block:: ini

       [DEFAULT]
       # ...
       interface_driver = linuxbridge
       dhcp_driver = neutron.agent.linux.dhcp.Dnsmasq
       enable_isolated_metadata = true

    .. end

Return to *Networking controller node configuration*.
