.. _manual_install:

==============================
Manual install & Configuration
==============================

  .. note::

     These instructions are intended for advanced users only, and could
     be incomplete. Please consult your distro-specific documentation
     for more details.

     It is also assumed you have already installed neutron components,
     see the latest `Install Tutorials and Guides <../index.html>`__ for
     more information.

This document discusses what is required for manual installation or
integration into a production OpenStack deployment tool of conventional
architectures that include the following types of nodes:

* Controller - Runs OpenStack control plane services such as REST APIs
  and databases.

* Network - Runs the layer-2, layer-3 (routing), DHCP, and metadata agents
  for the Networking service. Some agents optional. Usually provides
  connectivity between provider (public) and project (private) networks
  via NAT and floating IP addresses.

  .. note::

     Some tools deploy these services on controller nodes.

* Compute - Runs the hypervisor and layer-2 agent for the Networking
  service.

Packaging
---------

The Networking service integration for OVN is now one of the in-tree Neutron
drivers, so should be delivered with the ``neutron`` package, beginning with
the Ussuri release.

For deployment tools using distribution packages, the names of them are
different depending on the distribution.

#. RHEL/Fedora and compatible distributions include the ``ovn-central`` and
   ``ovn-host`` packages, which automatically install ``openvswitch`` as a
   dependency.

#. Ubuntu/Debian distributions include the ``ovn-central``, ``ovn-host``,
   ``ovn-common`` and ``ovn-docker`` packages, which automatically install
   the appropriate Open vSwitch dependencies as needed.

Controller nodes
----------------

Each controller node runs the Open vSwitch (OVS) service (including
dependent services such as ``ovsdb-server``) and ``ovn-northd``.
Only a single instance of the ``ovsdb-server`` and ``ovn-northd`` services
can operate in a deployment. However, deployment tools can implement
active/passive high-availability using a management tool that monitors
service health and automatically starts these services on another node after
failure of the primary node. See the :doc:`/ovn/faq/index` for more
information.

#. Install the ``ovn-central`` and ``openvswitch`` packages (RHEL/Fedora).

#. Install the ``ovn-central`` and ``openvswitch-common`` packages
   (Ubuntu/Debian).

#. Start the OVS service. The central OVS service starts the ``ovsdb-server``
   service that manages OVN databases.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start openvswitch (RHEL/Fedora)
      # systemctl start openvswitch-switch (Ubuntu/Debian)

#. Configure the ``ovsdb-server`` component. By default, the ``ovsdb-server``
   service only permits local access to databases via Unix socket. However,
   OVN services on compute nodes require access to these databases.

   * Permit remote database access.

     .. code-block:: console

        # ovn-nbctl set-connection ptcp:6641:0.0.0.0 -- \
                    set connection . inactivity_probe=60000
        # ovn-sbctl set-connection ptcp:6642:0.0.0.0 -- \
                    set connection . inactivity_probe=60000
        # if using the VTEP functionality:
        #   ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6640:0.0.0.0

     Replace ``0.0.0.0`` with the IP address of the management network
     interface on the controller node to avoid listening on all interfaces.

     .. note::

        Permit remote access to TCP ports: 6640 (OVS) to VTEPS (if you use
        vteps), 6642 (SBDB) to hosts running neutron-server, gateway nodes
        that run ovn-controller, and compute node services like ovn-controller
        and ovn-metadata-agent. 6641 (NBDB) to hosts running neutron-server.

    * Since we are using ``options:redirect-type`` set to ``bridged`` for Logical
      Router Ports in VLAN and FLAT networks, OVN redirects packets to the
      gateway chassis using the localnet port of the  router’s  peer  logical
      switch, instead of a tunnel. If ``external-ids:ovn-chassis-mac-mappings`` is
      not configured reply packets from VM on compute node leave physnet with
      source MAC address of Neutron Logical Router Port. Which cause MAC jump over
      computes and gateways. To avoid this setting
      ``external-ids:ovn-chassis-mac-mappings`` for each physnet with unique MAC
      address on each compute is required.

      Below you can find example how to set ``ovn-chassis-mac-mappings`` for
      compute host with two physical networks ``physnet1`` and ``physnet2``.
      For example you can take MAC address from physical interface that is plugged
      into physnet.

     .. code-block:: console

        # ovs-vsctl set open . external-ids:ovn-chassis-mac-mappings=\
            physnet1:aa:bb:cc:dd:ee:ff,physnet2:aa:bb:cc:dd:ee:fe

#. Start the ``ovn-northd`` service.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start ovn-northd

#. Configure the Networking server component. The Networking service
   implements OVN as an ML2 driver. Edit the ``/etc/neutron/neutron.conf``
   file:

   * Enable the ML2 core plug-in.

     .. code-block:: ini

        [DEFAULT]
        ...
        core_plugin = ml2

   * Enable the OVN layer-3 service.

     .. code-block:: ini

        [DEFAULT]
        ...
        service_plugins = ovn-router

#. Configure the ML2 plug-in. Edit the
   ``/etc/neutron/plugins/ml2/ml2_conf.ini`` file:

   * Configure the OVN mechanism driver, network type drivers, self-service
     (tenant) network types, and enable the port security extension.

     .. code-block:: ini

        [ml2]
        ...
        mechanism_drivers = ovn
        type_drivers = local,flat,vlan,geneve
        tenant_network_types = geneve
        extension_drivers = port_security
        overlay_ip_version = 4

     .. note::

        To enable VLAN self-service networks, make sure that OVN
        version 2.11 (or higher) is used, then add ``vlan`` to the
        ``tenant_network_types`` option. The first network type in the
        list becomes the default self-service network type.

        To use IPv6 for all overlay (tunnel) network endpoints,
        set the ``overlay_ip_version`` option to ``6``.

   * Configure the Geneve ID range and maximum header size. The IP version
     overhead (20 bytes for IPv4 (default) or 40 bytes for IPv6) is added
     to the maximum header size based on the ML2 ``overlay_ip_version``
     option.

     .. code-block:: ini

        [ml2_type_geneve]
        ...
        vni_ranges = 1:65536
        max_header_size = 38

     .. note::

        The Networking service uses the ``vni_ranges`` option to allocate
        network segments. However, OVN ignores the actual values. Thus, the ID
        range only determines the quantity of Geneve networks in the
        environment. For example, a range of ``5001:6000`` defines a maximum
        of 1000 Geneve networks. On the other hand, these values are still
        relevant in Neutron context so ``1:1000`` and ``5001:6000`` are *not*
        simply interchangeable.

      .. warning::

        The default for ``max_header_size``, ``30``, is too low for OVN.
        OVN requires at least ``38``.

   * Optionally, enable support for VXLAN type networks. Because of limited
     space in VXLAN VNI to pass over the needed information that requires
     OVN to identify a packet, the header size to contain the segmentation ID
     is reduced to 12 bits, that allows a maximum number of 4096 networks.
     The same limitation applies to the number of ports in each network, that
     are also identified with a 12 bits header chunk, limiting their number
     to 4096 ports. Please check [1]_ for more information.

     .. code-block:: ini

        [ml2]
        ...
        type_drivers = geneve,vxlan

        [ml2_type_vxlan]
        vni_ranges = 1001:1100

   * Optionally, enable support for VLAN provider and self-service
     networks on one or more physical networks. If you specify only
     the physical network, only administrative (privileged) users can
     manage VLAN networks. Additionally specifying a VLAN ID range for
     a physical network enables regular (non-privileged) users to
     manage VLAN networks. The Networking service allocates the VLAN ID
     for each self-service network using the VLAN ID range for the
     physical network.

     .. code-block:: ini

        [ml2_type_vlan]
        ...
        network_vlan_ranges = PHYSICAL_NETWORK:MIN_VLAN_ID:MAX_VLAN_ID

     Replace ``PHYSICAL_NETWORK`` with the physical network name and
     optionally define the minimum and maximum VLAN IDs. Use a comma
     to separate each physical network.

     For example, to enable support for administrative VLAN networks
     on the ``physnet1`` network and self-service VLAN networks on
     the ``physnet2`` network using VLAN IDs 1001 to 2000:

     .. code-block:: ini

        network_vlan_ranges = physnet1,physnet2:1001:2000

   * Enable security groups.

     .. code-block:: ini

        [securitygroup]
        ...
        enable_security_group = true

     .. note::

        The ``firewall_driver`` option under ``[securitygroup]`` is ignored
        since the OVN ML2 driver itself handles security groups.

   * Configure OVS database access and L3 scheduler

     .. code-block:: ini

        [ovn]
        ...
        ovn_nb_connection = tcp:IP_ADDRESS:6641
        ovn_sb_connection = tcp:IP_ADDRESS:6642
        ovn_l3_scheduler = OVN_L3_SCHEDULER

     .. note::

        Replace ``IP_ADDRESS`` with the IP address of the controller node that
        runs the ``ovsdb-server`` service. Replace ``OVN_L3_SCHEDULER`` with
        ``leastloaded`` if you want the scheduler to select a compute node with
        the least number of gateway ports or ``chance`` if you want the
        scheduler to randomly select a compute node from the available list of
        compute nodes.

   * Set ovn-cms-options with enable-chassis-as-gw in Open_vSwitch table's
     external_ids column. Then if this chassis has proper bridge mappings,
     it will be selected for scheduling gateway routers.

     .. code-block:: console

        # ovs-vsctl set open . external-ids:ovn-cms-options=enable-chassis-as-gw

#. Start, or restart, the ``neutron-server`` service.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start neutron-server

Network nodes
-------------

Deployments using OVN native layer-3 and DHCP services do not require
conventional network nodes because connectivity to external networks
(including VTEP gateways) and routing occurs on compute nodes.

Compute nodes
-------------

Each compute node runs the OVS and ``ovn-controller`` services. The
``ovn-controller`` service replaces the conventional OVS layer-2 agent.

#. Install the ``ovn-host``, ``openvswitch`` and
   ``neutron-ovn-metadata-agent`` packages (RHEL/Fedora).

#. Install the ``ovn-host``, ``openvswitch-switch`` and
   ``neutron-ovn-metadata-agent`` packages (Ubuntu/Debian).

#. Start the OVS service.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start openvswitch (RHEL/Fedora)
      # systemctl start openvswitch-switch (Ubuntu/Debian)

#. Configure the OVS service.

   * Use OVS databases on the controller node.

     .. code-block:: console

        # ovs-vsctl set open . external-ids:ovn-remote=tcp:IP_ADDRESS:6642

     Replace ``IP_ADDRESS`` with the IP address of the controller node
     that runs the ``ovsdb-server`` service.

   * Enable one or more overlay network protocols. At a minimum, OVN requires
     enabling the ``geneve`` protocol. Deployments using VTEP gateways should
     also enable the ``vxlan`` protocol.

     .. code-block:: console

        # ovs-vsctl set open . external-ids:ovn-encap-type=geneve,vxlan

     .. note::

        Deployments without VTEP gateways can safely enable both protocols.

   * Configure the overlay network local endpoint IP address.

     .. code-block:: console

        # ovs-vsctl set open . external-ids:ovn-encap-ip=IP_ADDRESS

     Replace ``IP_ADDRESS`` with the IP address of the overlay network
     interface on the compute node.

#. Start the ``ovn-controller`` and ``neutron-ovn-metadata-agent`` services.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start ovn-controller neutron-ovn-metadata-agent

Verify operation
----------------

#. Each compute node should contain an ``ovn-controller`` instance.

   .. code-block:: console

      # ovn-sbctl show
        <output>

References
----------

.. [1] https://mail.openvswitch.org/pipermail/ovs-dev/2020-September/375189.html
